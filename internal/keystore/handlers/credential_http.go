// credential_http.go — the credential_http_request handler: the Keeper's
// decrypt-to-tool HTTP sink for the MCP Credential Control Plane.
//
// This is the Keeper's first network surface, so every step is a guardrail. The
// handler opens a sealed credential payload under the raw Group DEK behind the
// opaque handle (AAD-bound, like group_encrypt_with_aad's inverse), substitutes
// the decrypted secret into the caller's header and query templates, performs a
// single locked-down HTTPS request, and returns a redacted response. The plaintext
// credential is assembled, used, and zeroized entirely inside the Keeper — it
// appears zero times in the IPC response and the logs.
//
// Everything up to and including the open is credential_open.go's
// openCredentialForSink, shared with the exec sink; what lives here is the HTTP
// half of the policy check and the request itself.
//
// The nine in-Keeper safeguards:
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
//  9. query_template rendering — the credential is appended to the target's
//     query only after every policy check has run against the pre-injection URL,
//     and the rewritten URL is stripped out of transport errors (unwrapURLError)
//     so it never reaches an IPC response.

package handlers

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

const (
	// These limits are Keeper-owned and are not caller-configurable because the
	// server policy signature does not cover resource-limit fields.
	defaultCredentialTimeout = 30 * time.Second
	defaultMaxRespBytes      = 1 << 20 // 1 MiB
)

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

	// Safeguard 1: everything the signed policy pins about *this* request. It
	// runs inside the prelude — after the signature is verified, before the
	// payload is opened — which is the slot the exec sink's command check
	// occupies too. body is decoded here rather than earlier so it keeps its
	// place in that order.
	var body []byte
	matchPolicy := func() (bool, proto.BaseResponse) {
		if !executionTargetMatches(req.TargetURL, req.Method, req.Policy) {
			return false, errs.CodeResponse(errs.ErrCodeValidation,
				"request target does not match signed execution target")
		}
		if !hostAllowed(host, req.Policy.AllowedHosts) {
			return false, errs.CodeResponse(errs.ErrCodeValidation, "target host is not in policy.allowed_hosts")
		}
		if !methodAllowed(req.Method, req.Policy.AllowedMethods) {
			return false, errs.CodeResponse(errs.ErrCodeValidation, "method is not in policy.allowed_methods")
		}
		if !pathAllowed(req.TargetURL, req.Policy.AllowedPathPatterns) {
			return false, errs.CodeResponse(errs.ErrCodeValidation, "target path is not in policy.allowed_path_patterns")
		}
		if !requestShapeAllowed(req.TargetURL, req.BodyB64 != "", req.Policy.AllowQuery, req.Policy.AllowBody) {
			return false, errs.CodeResponse(errs.ErrCodeValidation, "query or body is not allowed by credential policy")
		}
		if !headerTemplatesEqual(req.HeaderTemplate, req.Policy.HeaderTemplate) {
			return false, errs.CodeResponse(errs.ErrCodeValidation, "header_template does not match signed credential policy")
		}
		if !queryTemplatesEqual(req.QueryTemplate, req.Policy.QueryTemplate) {
			return false, errs.CodeResponse(errs.ErrCodeValidation, "query_template does not match signed credential policy")
		}
		if req.BodyB64 != "" {
			decoded, resp, ok := decodeBase64(req.BodyB64, "body_b64")
			if !ok {
				return false, resp
			}
			body = decoded
		}
		return true, proto.BaseResponse{}
	}

	// Safeguard 8 (part): the prelude decrypts inside the session lock and hands
	// back the zeroizer for the plaintext.
	secret, cleanup, resp, ok := openCredentialForSink(d, credentialRequestCommon{
		keySource: credentialKeySource{
			groupHandle:         req.GroupHandle,
			encryptedDEKB64:     req.EncryptedDEKB64,
			useLocalPersonalDEK: req.UseLocalPersonalDEK,
		},
		ivB64:         req.IVB64,
		ciphertextB64: req.CiphertextB64,
		aadB64:        req.AADB64,
		policy:        req.Policy,
		action:        "credential http request",
	}, matchPolicy)
	defer cleanup()
	if !ok {
		return resp
	}

	// Assemble outbound headers from the {{secret.<key>}} placeholders.
	headers, injected, err := substituteSecretHeaders(req.HeaderTemplate, secret)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeValidation, err.Error())
	}

	// Safeguard 9: render query_template into the target's query. Every policy
	// check above ran against req.TargetURL — the pre-injection URL — and the
	// rewritten one exists only from here to the transport. It carries the
	// credential in the clear, so it must never reach a log line, an error
	// string, or any returned field; injectSecretQuery adds the rendered values
	// to injected so redaction covers a query secret echoed back.
	targetURL, injected, err := injectSecretQuery(req.TargetURL, req.QueryTemplate, secret, injected)
	if err != nil {
		wipeSecretStrings(headers)
		return errs.CodeResponse(errs.ErrCodeValidation, err.Error())
	}

	data, reqErr := doCredentialRequest(req.Method, targetURL, headers, body, injected,
		defaultCredentialTimeout, defaultMaxRespBytes)

	// Safeguard 8 (part): drop references to the assembled secret strings now
	// that the request is done. (Go strings are immutable, so this is a
	// best-effort reference drop; the decrypted payload buffer cleanup zeroizes
	// is the byte slice that gets truly wiped.)
	wipeSecretStrings(headers)

	if reqErr != nil {
		// doCredentialRequest already strips the request URL out of transport
		// errors (unwrapURLError); masking is the second line, covering any
		// future error path that reconstructs it.
		return errs.CodeResponse(errs.ErrCodeInternal,
			maskSecrets("credential request failed: "+reqErr.Error(), injected))
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
	// targetURL may carry an injected credential in its query, and both
	// http.NewRequest and client.Do wrap failures in a *url.Error whose message
	// embeds it verbatim. Every error leaving this function is reduced to its
	// cause first.
	httpReq, err := http.NewRequest(strings.ToUpper(strings.TrimSpace(method)), targetURL, bodyReader)
	if err != nil {
		return proto.CredentialHTTPResponseData{}, unwrapURLError(err)
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
		return proto.CredentialHTTPResponseData{}, unwrapURLError(err)
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
