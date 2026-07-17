// credential_http.go — payload models for credential_http_request, the MCP
// Credential Control Plane's decrypt-to-tool HTTP action.
//
// The request carries a sealed credential payload (iv / ciphertext / aad, opened
// under the raw Group DEK behind the opaque handle exactly like
// group_encrypt_with_aad's inverse), the outbound request description
// (target_url / method / header_template / body), and the enforcement policy.
// No raw secret is present in the request: header_template values are
// {{secret.<key>}} placeholders, resolved against the decrypted payload inside
// the Keeper. The response carries only redacted material.
//
// Validate() covers structural checks (handle shape, Base64 fields, non-empty
// target/method, a policy with at least one allowed host and method). The
// security safeguards (host exact-match, SSRF blocking, HTTPS enforcement,
// redirect blocking, size cap, timeout, redaction) are the handler's job and are
// re-checked there regardless of what Validate accepted.

package proto

// CredentialPolicy is the caller-supplied enforcement policy re-validated inside
// the Keeper before the outbound request. allowed_hosts is the host allowlist
// (MVP: at least one, exact host match after normalization); allowed_methods is
// the HTTP method allowlist. max_resp_bytes / timeout_ms are optional and fall
// back to the handler defaults when non-positive.
//
// (Policy is carried as request data here. The design's server-signed policy —
// verified in-Keeper to stop MCP tampering — is a follow-up that adds a
// signature field + server public-key plumbing; it is not part of this contract.)
type CredentialPolicy struct {
	AllowedHosts   []string `json:"allowed_hosts"`
	AllowedMethods []string `json:"allowed_methods"`
	MaxRespBytes   int64    `json:"max_resp_bytes,omitempty"`
	TimeoutMs      int64    `json:"timeout_ms,omitempty"`
}

// CredentialHTTPRequest is the decrypt-to-tool request. RequestID correlation is
// carried by the BaseRequest envelope (echoed by the Keeper), so it is not
// duplicated here.
type CredentialHTTPRequest struct {
	GroupHandle   string `json:"group_handle"`
	IVB64         string `json:"iv_b64"`         // 12B IV, public material
	CiphertextB64 string `json:"ciphertext_b64"` // sealed payload (public material)
	AADB64        string `json:"aad_b64"`        // canonical AAD, opened byte-identically (public material)

	TargetURL string `json:"target_url"`
	Method    string `json:"method"`
	// HeaderTemplate carries only {{secret.<key>}} placeholders, e.g.
	// {"Authorization":"Bearer {{secret.token}}"}; the raw secret never appears
	// here. Resolved against the decrypted payload's secret map inside the Keeper.
	HeaderTemplate map[string]string `json:"header_template"`
	BodyB64        string            `json:"body_b64,omitempty"` // request body, public material

	Policy CredentialPolicy `json:"policy"`
}

func (r CredentialHTTPRequest) Validate() error {
	if err := requireHandle(r.GroupHandle, "group_handle"); err != nil {
		return err
	}
	if _, err := requireBase64Len(r.IVB64, "iv_b64", 12); err != nil {
		return err
	}
	if _, err := requireBase64(r.CiphertextB64, "ciphertext_b64"); err != nil {
		return err
	}
	// AAD is required and opened byte-identically — the sealed payload is bound
	// to its canonical context (org_id|entry_id|payload_kind|schema_version|
	// dek_version), so an empty AAD is never valid here.
	if _, err := requireBase64(r.AADB64, "aad_b64"); err != nil {
		return err
	}
	if err := requireString(r.TargetURL, "target_url"); err != nil {
		return err
	}
	if err := requireString(r.Method, "method"); err != nil {
		return err
	}
	// The whole point of the action is to inject the decrypted secret into the
	// outbound headers, so an empty template has no legitimate caller.
	if len(r.HeaderTemplate) == 0 {
		return newValidationError("header_template", "must not be empty")
	}
	if len(r.Policy.AllowedHosts) == 0 {
		return newValidationError("policy.allowed_hosts", "must list at least one host")
	}
	if len(r.Policy.AllowedMethods) == 0 {
		return newValidationError("policy.allowed_methods", "must list at least one method")
	}
	return nil
}

// CredentialHTTPResponseData is the redacted outbound-request result. It never
// carries the plaintext credential or the injected header values: Authorization /
// Set-Cookie / Proxy-Authorization response headers are stripped, and any echo
// of the injected secret in the body is masked before Base64 encoding.
type CredentialHTTPResponseData struct {
	StatusCode int               `json:"status_code"`
	Headers    map[string]string `json:"headers"`   // redacted response headers
	BodyB64    string            `json:"body_b64"`  // redacted response body, Base64
	Truncated  bool              `json:"truncated"` // true when the body hit max_resp_bytes
}
