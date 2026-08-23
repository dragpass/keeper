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
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/awnumar/memguard"

	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/secure"
)

const (
	// These limits are Keeper-owned and are not caller-configurable because the
	// server policy signature does not cover resource-limit fields.
	defaultCredentialTimeout = 30 * time.Second
	defaultMaxRespBytes      = 1 << 20 // 1 MiB
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
	if ok, resp := verifyCredentialPolicy(d, aad, req.Policy); !ok {
		return resp
	}
	if !executionTargetMatches(req.TargetURL, req.Method, req.Policy) {
		return errs.CodeResponse(errs.ErrCodeValidation, "request target does not match signed execution target")
	}

	// The signed policy is trusted only after verification above.
	if !hostAllowed(host, req.Policy.AllowedHosts) {
		return errs.CodeResponse(errs.ErrCodeValidation, "target host is not in policy.allowed_hosts")
	}
	if !methodAllowed(req.Method, req.Policy.AllowedMethods) {
		return errs.CodeResponse(errs.ErrCodeValidation, "method is not in policy.allowed_methods")
	}
	if !pathAllowed(req.TargetURL, req.Policy.AllowedPathPatterns) {
		return errs.CodeResponse(errs.ErrCodeValidation, "target path is not in policy.allowed_path_patterns")
	}
	if !requestShapeAllowed(req.TargetURL, req.BodyB64 != "", req.Policy.AllowQuery, req.Policy.AllowBody) {
		return errs.CodeResponse(errs.ErrCodeValidation, "query or body is not allowed by credential policy")
	}
	if !headerTemplatesEqual(req.HeaderTemplate, req.Policy.HeaderTemplate) {
		return errs.CodeResponse(errs.ErrCodeValidation, "header_template does not match signed credential policy")
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
	useErr := withCredentialDEK(d, req, func(dek []byte) error {
		pt, err := AESGCMOpenWithAAD(dek, iv, ciphertext, aad)
		if err != nil {
			decErr = err
			return nil
		}
		payload = pt
		return nil
	})
	if useErr != nil {
		return sessionUseError(useErr, "credential http request")
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
		defaultCredentialTimeout, defaultMaxRespBytes)

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

	// Safeguard 7 (part): the Keeper can only redact bytes it can read. The Go
	// transport transparently decodes gzip *only* when it owns the negotiation —
	// any caller-set Accept-Encoding switches that off and hands the encoding
	// choice to the policy author. Drop it so we always ask for something we
	// decode ourselves.
	httpReq.Header.Del("Accept-Encoding")

	client := newSecureHTTPClient(timeout)
	httpResp, err := client.Do(httpReq)
	if err != nil {
		return proto.CredentialHTTPResponseData{}, err
	}
	defer httpResp.Body.Close()

	// Safeguard 7 (part): refuse a body we cannot inspect. The transport strips
	// Content-Encoding after decoding gzip, so anything left here (br, zstd,
	// deflate, ...) is opaque to redactBody — a secret echoed inside it would
	// survive as compressed bytes and reach the model, which can decode it.
	// Fail closed rather than forward it.
	if encoding := undecodableContentEncoding(httpResp.Header); encoding != "" {
		return proto.CredentialHTTPResponseData{},
			fmt.Errorf("response content-encoding %q cannot be inspected for redaction", encoding)
	}

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
		Headers:    redactResponseHeaders(httpResp.Header, injected),
		BodyB64:    base64.StdEncoding.EncodeToString(raw),
		Truncated:  truncated,
	}, nil
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

// withCredentialDEK yields the DEK that opens the sealed payload, dispatching
// on which key source the request carries. Validate() has already enforced
// exactly one.
//
// Both scopes run the *same* decrypt-to-tool body — every one of the eight
// safeguards lives once, above. Duplicating this handler per scope is how two
// copies of a security sink drift apart, so only the key source is branched.
//
//   - org      : raw Group DEK inside the GroupSessionStore memguard lock.
//   - personal : device-wrapped personal DEK unwrapped here and zeroized on
//     return. The device key is fetched from the Keeper Keychain, never IPC.
func withCredentialDEK(d Deps, req proto.CredentialHTTPRequest, fn func(dek []byte) error) error {
	if req.GroupHandle != "" {
		return d.GroupSessions.Use(req.GroupHandle, fn)
	}

	deviceKey, err := loadDeviceKeyFromKeychain(d.Store)
	if err != nil {
		return err
	}
	deviceKeyBuf := memguard.NewBufferFromBytes(deviceKey)
	defer deviceKeyBuf.Destroy()

	dek, err := unwrapDeviceWrappedDEK(deviceKeyBuf.Bytes(), req.EncryptedDEKB64)
	if err != nil {
		return err
	}
	defer secure.Zeroize(dek)

	return fn(dek)
}
