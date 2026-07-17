// credential_http.go — the credential_http_request handler: the Keeper's
// decrypt-to-tool HTTP sink for the MCP Credential Control Plane.
//
// This is the Keeper's first network surface, so every step is a guardrail. The
// handler opens a sealed credential payload under the raw Group DEK behind the
// opaque handle (AAD-bound, like group_encrypt_with_aad's inverse), substitutes
// the decrypted secret into the caller's header template, performs a single
// locked-down HTTPS request, and returns a redacted response. The plaintext
// credential is assembled, used, and zeroized entirely inside the Keeper — it
// appears zero times in the IPC response and the logs.
//
// The eight in-Keeper safeguards:
//  1. policy re-validation — target host exact-match against policy.allowed_hosts,
//     method allowlist (hostAllowed / methodAllowed).
//  2. SSRF / private-IP blocking — the outbound client's Dialer.Control hook
//     re-checks the resolved IP at connect time (isBlockedIP), so DNS rebinding
//     to a private / metadata address is refused before any bytes are sent.
//  3. HTTPS only, TLS verification on (enforceHTTPSURL + newSecureHTTPClient).
//  4. all redirects blocked (CheckRedirect → ErrUseLastResponse).
//  5. response size cap + truncation flag (io.LimitReader).
//  6. request timeout (client Timeout, from policy or default).
//  7. response redaction (redactResponseHeaders / redactBody).
//  8. decrypted payload + assembled secret strings zeroized / dropped after use.

package handlers

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/secure"
)

const (
	// defaultCredentialTimeout is used when policy.timeout_ms is non-positive.
	defaultCredentialTimeout = 30 * time.Second
	// maxCredentialTimeout caps policy.timeout_ms so a hostile / buggy caller
	// cannot pin an outbound connection open indefinitely.
	maxCredentialTimeout = 120 * time.Second
	// defaultMaxRespBytes is used when policy.max_resp_bytes is non-positive.
	defaultMaxRespBytes = 1 << 20 // 1 MiB
)

// sealedCredential is the decrypted payload shape. Only the fields the Keeper
// needs to assemble headers are modeled; everything else in the payload JSON is
// ignored. secret is the {key: value} map the {{secret.<key>}} placeholders
// resolve against.
type sealedCredential struct {
	Type   string            `json:"type"`
	Secret map[string]string `json:"secret"`
}

// HandleCredentialHTTPRequest opens the sealed credential, injects it into the
// header template, performs the guarded outbound request, and returns the
// redacted result.
func HandleCredentialHTTPRequest(d Deps, req proto.CredentialHTTPRequest) proto.BaseResponse {
	d.Logger.Println("credential http request processing...")

	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}

	// Safeguard 3 (part): HTTPS-only target, extract the host.
	host, err := enforceHTTPSURL(req.TargetURL)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeValidation, err.Error())
	}

	// Safeguard 1: policy re-validation — host exact-match + method allowlist.
	if !hostAllowed(host, req.Policy.AllowedHosts) {
		return errs.CodeResponse(errs.ErrCodeValidation, "target host is not in policy.allowed_hosts")
	}
	if !methodAllowed(req.Method, req.Policy.AllowedMethods) {
		return errs.CodeResponse(errs.ErrCodeValidation, "method is not in policy.allowed_methods")
	}

	// Decode the public material (IV / ciphertext / AAD / optional body).
	iv, resp, ok := decodeBase64Len(req.IVB64, 12, "iv_b64")
	if !ok {
		return resp
	}
	ciphertext, resp, ok := decodeBase64(req.CiphertextB64, "ciphertext_b64")
	if !ok {
		return resp
	}
	aad, resp, ok := decodeBase64(req.AADB64, "aad_b64")
	if !ok {
		return resp
	}
	var body []byte
	if req.BodyB64 != "" {
		body, resp, ok = decodeBase64(req.BodyB64, "body_b64")
		if !ok {
			return resp
		}
	}

	// Safeguard 8 (part): decrypt inside the session lock, keep the plaintext in
	// a local slice, and zeroize it on return. AAD mismatch (a swapped sealed
	// payload) fails the open here.
	var payload []byte
	var decErr error
	useErr := d.GroupSessions.Use(req.GroupHandle, func(groupDEK []byte) error {
		pt, err := AESGCMOpenWithAAD(groupDEK, iv, ciphertext, aad)
		if err != nil {
			decErr = err
			return nil
		}
		payload = pt
		return nil
	})
	if useErr != nil {
		return groupSessionUseError(useErr, "credential http request")
	}
	if decErr != nil {
		// Generic message — never echo the decrypt error detail.
		return errs.CodeResponse(errs.ErrCodeCryptoFailure, "sealed payload decrypt failed")
	}
	defer secure.Zeroize(payload)

	var cred sealedCredential
	if err := json.Unmarshal(payload, &cred); err != nil {
		return errs.CodeResponse(errs.ErrCodeCryptoFailure, "sealed payload is not a valid credential")
	}

	// Assemble outbound headers from the {{secret.<key>}} placeholders.
	headers, injected, err := substituteSecretHeaders(req.HeaderTemplate, cred.Secret)
	if err != nil {
		wipeSecretStrings(cred.Secret)
		return errs.CodeResponse(errs.ErrCodeValidation, err.Error())
	}

	data, reqErr := doCredentialRequest(req.Method, req.TargetURL, headers, body, injected,
		resolveTimeout(req.Policy.TimeoutMs), resolveMaxRespBytes(req.Policy.MaxRespBytes))

	// Safeguard 8 (part): drop references to the assembled secret strings and the
	// parsed secret map now that the request is done. (Go strings are immutable,
	// so this is a best-effort reference drop; the decrypted payload buffer above
	// is the byte slice that gets truly zeroized.)
	wipeSecretStrings(cred.Secret)
	wipeSecretStrings(headers)

	if reqErr != nil {
		return errs.CodeResponse(errs.ErrCodeInternal, "credential request failed: "+reqErr.Error())
	}

	d.Logger.Println("credential http request successful")
	return proto.BaseResponse{Success: true, Data: data}
}

// doCredentialRequest performs the single guarded outbound request and builds
// the redacted response. Safeguards 2/3/4/6 live in newSecureHTTPClient; 5 and 7
// are applied here.
func doCredentialRequest(method, targetURL string, headers map[string]string, body []byte,
	injected []string, timeout time.Duration, maxRespBytes int64) (proto.CredentialHTTPResponseData, error) {

	var bodyReader io.Reader
	if len(body) > 0 {
		bodyReader = bytes.NewReader(body)
	}
	httpReq, err := http.NewRequest(strings.ToUpper(strings.TrimSpace(method)), targetURL, bodyReader)
	if err != nil {
		return proto.CredentialHTTPResponseData{}, err
	}
	for name, value := range headers {
		httpReq.Header.Set(name, value)
	}

	client := newSecureHTTPClient(timeout)
	httpResp, err := client.Do(httpReq)
	if err != nil {
		return proto.CredentialHTTPResponseData{}, err
	}
	defer httpResp.Body.Close()

	// Safeguard 5: read at most maxRespBytes (+1 to detect overflow) and flag
	// truncation.
	raw, err := io.ReadAll(io.LimitReader(httpResp.Body, maxRespBytes+1))
	if err != nil {
		return proto.CredentialHTTPResponseData{}, err
	}
	truncated := false
	if int64(len(raw)) > maxRespBytes {
		raw = raw[:maxRespBytes]
		truncated = true
	}

	// Safeguard 7: mask any secret echoed in the body; strip credential headers.
	raw = redactBody(raw, injected)

	return proto.CredentialHTTPResponseData{
		StatusCode: httpResp.StatusCode,
		Headers:    redactResponseHeaders(httpResp.Header),
		BodyB64:    base64.StdEncoding.EncodeToString(raw),
		Truncated:  truncated,
	}, nil
}

// resolveTimeout returns the client timeout, defaulting when non-positive and
// clamping to the ceiling.
func resolveTimeout(timeoutMs int64) time.Duration {
	if timeoutMs <= 0 {
		return defaultCredentialTimeout
	}
	t := time.Duration(timeoutMs) * time.Millisecond
	if t > maxCredentialTimeout {
		return maxCredentialTimeout
	}
	return t
}

// resolveMaxRespBytes returns the response size cap, defaulting when non-positive.
func resolveMaxRespBytes(maxRespBytes int64) int64 {
	if maxRespBytes <= 0 {
		return defaultMaxRespBytes
	}
	return maxRespBytes
}

// wipeSecretStrings drops references to secret-bearing map values. Go strings
// are immutable so this cannot overwrite the backing bytes; it removes the last
// reference so the value is eligible for GC. The truly zeroized secret is the
// decrypted payload []byte in the handler.
func wipeSecretStrings(m map[string]string) {
	for k := range m {
		m[k] = ""
	}
}
