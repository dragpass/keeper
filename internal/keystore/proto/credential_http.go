// credential_http.go — payload models for credential_http_request, the MCP
// Credential Control Plane's decrypt-to-tool HTTP action.
//
// The request carries a sealed credential payload (iv / ciphertext / aad, opened
// under the raw Group DEK behind the opaque handle exactly like
// group_encrypt_with_aad's inverse), the outbound request description
// (target_url / method / header_template / query_template / body), and the
// enforcement policy. No raw secret is present in the request: header_template
// and query_template values are {{secret.<key>}} placeholders, resolved against
// the decrypted payload inside the Keeper. The response carries only redacted
// material.
//
// Validate() covers structural checks (handle shape, Base64 fields, non-empty
// target/method, a policy with at least one allowed host and method). The
// security safeguards (host exact-match, SSRF blocking, HTTPS enforcement,
// redirect blocking, size cap, timeout, redaction) are the handler's job and are
// re-checked there regardless of what Validate accepted.

package proto

// CredentialPolicy is the server-signed enforcement policy verified inside the
// Keeper before the outbound request. The signature binds the entry, payload DEK
// version, host/method allowlists, and expiry. Limits remain Keeper-owned constants
// so an untrusted MCP process cannot widen them through unsigned request fields.
type CredentialPolicy struct {
	EntryID             string            `json:"entry_id"`
	DekVersion          int               `json:"dek_version"`
	AllowedHosts        []string          `json:"allowed_hosts"`
	AllowedMethods      []string          `json:"allowed_methods"`
	AllowedPathPatterns []string          `json:"allowed_path_patterns"`
	HeaderTemplate      map[string]string `json:"header_template"`
	// QueryTemplate carries the same {{secret.<key>}} placeholders as
	// HeaderTemplate, for credentials the target API only accepts as a query
	// parameter. Omitted (nil) for every header / cookie credential, and the
	// canonical policy string leaves the slot out entirely when it is empty —
	// so a policy without query injection signs exactly as it did before this
	// field existed.
	QueryTemplate map[string]string `json:"query_template,omitempty"`
	AllowQuery    bool              `json:"allow_query"`
	AllowBody     bool              `json:"allow_body"`
	TargetHost    string            `json:"target_host"`
	TargetPath    string            `json:"target_path"`
	Method        string            `json:"method"`
	// ExecExecutable / ExecArgv / ExecCwd / EnvTemplate — the exec sink's signed
	// command (credential_exec_request). The exec sink has no network target to
	// pin, so what the signature binds instead is the exact command a human
	// approved: the absolute executable, the whole argv (argv[0] == the
	// executable), and the working directory. EnvTemplate carries the same
	// {{secret.<key>}} placeholders HeaderTemplate does, keyed by environment
	// variable name.
	//
	// All four are absent for every HTTP policy, and the canonical policy string
	// appends the exec block only when EnvTemplate is non-empty — so a header /
	// cookie / query policy signs exactly the bytes it did before these fields
	// existed.
	ExecExecutable string            `json:"exec_executable,omitempty"`
	ExecArgv       []string          `json:"exec_argv,omitempty"`
	ExecCwd        string            `json:"exec_cwd,omitempty"`
	EnvTemplate    map[string]string `json:"env_template,omitempty"`

	ApprovalMode     string `json:"approval_mode"`
	Expiry           string `json:"expiry"`
	Signature        string `json:"signature"`
	ServerKeyVersion uint   `json:"server_key_version"`
	SignatureAlg     string `json:"signature_alg"`
}

// CredentialHTTPRequest is the decrypt-to-tool request. RequestID correlation is
// carried by the BaseRequest envelope (echoed by the Keeper), so it is not
// duplicated here.
type CredentialHTTPRequest struct {
	// Exactly one key source. GroupHandle opens an org-scope sealed payload.
	// EncryptedDEKB64 opens an explicitly supplied device-wrapped personal DEK.
	// UseLocalPersonalDEK reads that wrapped value from the Keeper Keychain, so
	// MCP does not receive key material.
	GroupHandle         string `json:"group_handle,omitempty"`
	EncryptedDEKB64     string `json:"encrypted_dek_b64,omitempty"`
	UseLocalPersonalDEK bool   `json:"use_local_personal_dek,omitempty"`
	IVB64               string `json:"iv_b64"`         // 12B IV, public material
	CiphertextB64       string `json:"ciphertext_b64"` // sealed payload (public material)
	AADB64              string `json:"aad_b64"`        // canonical AAD, opened byte-identically (public material)

	TargetURL string `json:"target_url"`
	Method    string `json:"method"`
	// HeaderTemplate carries only {{secret.<key>}} placeholders, e.g.
	// {"Authorization":"Bearer {{secret.token}}"}; the raw secret never appears
	// here. Resolved against the decrypted payload's secret map inside the Keeper.
	HeaderTemplate map[string]string `json:"header_template"`
	// QueryTemplate is the query-parameter sibling of HeaderTemplate: the
	// rendered values are appended to target_url's query inside the Keeper.
	// target_url itself is never template-substituted.
	QueryTemplate map[string]string `json:"query_template,omitempty"`
	BodyB64       string            `json:"body_b64,omitempty"` // request body, public material

	Policy CredentialPolicy `json:"policy"`
}

// validateCredentialKeySource enforces "exactly one key source" and the shape of
// whichever one was supplied. Both credential actions open the same sealed
// payload the same three ways, so the rule lives once — a second copy is how the
// two sinks drift apart.
//
// Accepting two sources would leave which key actually opened the payload
// ambiguous; accepting none has no caller.
func validateCredentialKeySource(groupHandle, encryptedDEKB64 string, useLocalPersonalDEK bool) error {
	sources := 0
	if groupHandle != "" {
		sources++
	}
	if encryptedDEKB64 != "" {
		sources++
	}
	if useLocalPersonalDEK {
		sources++
	}
	if sources != 1 {
		return newValidationError("group_handle", "exactly one key source is required")
	}
	switch {
	case groupHandle != "":
		if err := requireHandle(groupHandle, "group_handle"); err != nil {
			return err
		}
	case encryptedDEKB64 != "":
		if _, err := requireBase64(encryptedDEKB64, "encrypted_dek_b64"); err != nil {
			return err
		}
	}
	return nil
}

// validateCredentialSealedPayload checks the public material that carries the
// sealed credential. AAD is required and opened byte-identically — the sealed
// payload is bound to its canonical context (org_id or account_id, then
// entry_id|payload_kind|schema_version|dek_version), so an empty AAD is never
// valid here.
func validateCredentialSealedPayload(ivB64, ciphertextB64, aadB64 string) error {
	if _, err := requireBase64Len(ivB64, "iv_b64", 12); err != nil {
		return err
	}
	if _, err := requireBase64(ciphertextB64, "ciphertext_b64"); err != nil {
		return err
	}
	if _, err := requireBase64(aadB64, "aad_b64"); err != nil {
		return err
	}
	return nil
}

// validateCredentialPolicyEnvelope checks the signature envelope every signed
// credential policy carries, independent of which sink will enforce it.
func validateCredentialPolicyEnvelope(p CredentialPolicy) error {
	if p.EntryID == "" {
		return newValidationError("policy.entry_id", "must not be empty")
	}
	if p.DekVersion < 1 {
		return newValidationError("policy.dek_version", "must be >= 1")
	}
	if p.Expiry == "" {
		return newValidationError("policy.expiry", "must not be empty")
	}
	if p.Signature == "" {
		return newValidationError("policy.signature", "must not be empty")
	}
	if p.ServerKeyVersion < 1 {
		return newValidationError("policy.server_key_version", "must be >= 1")
	}
	if p.SignatureAlg == "" {
		return newValidationError("policy.signature_alg", "must not be empty")
	}
	return nil
}

// CredentialExecArgvEqual reports whether a request-supplied argv is exactly the
// one the server signed, element for element.
func CredentialExecArgvEqual(actual, signed []string) bool {
	if len(actual) != len(signed) {
		return false
	}
	for i := range actual {
		if actual[i] != signed[i] {
			return false
		}
	}
	return true
}

// CredentialTemplatesEqual reports whether a request-supplied template is
// exactly the one the server signed. A nil map and an empty map compare equal.
func CredentialTemplatesEqual(actual, signed map[string]string) bool {
	if len(actual) != len(signed) {
		return false
	}
	for key, value := range signed {
		if actual[key] != value {
			return false
		}
	}
	return true
}

func (r CredentialHTTPRequest) Validate() error {
	if err := validateCredentialKeySource(r.GroupHandle, r.EncryptedDEKB64, r.UseLocalPersonalDEK); err != nil {
		return err
	}
	if err := validateCredentialSealedPayload(r.IVB64, r.CiphertextB64, r.AADB64); err != nil {
		return err
	}
	if err := requireString(r.TargetURL, "target_url"); err != nil {
		return err
	}
	if err := requireString(r.Method, "method"); err != nil {
		return err
	}
	// The whole point of the action is to inject the decrypted secret into the
	// outbound request, so a caller that supplies neither template has no
	// legitimate use — the request would go out without the credential.
	if len(r.HeaderTemplate) == 0 && len(r.QueryTemplate) == 0 {
		return newValidationError("header_template", "header_template or query_template must not be empty")
	}
	if len(r.Policy.AllowedHosts) == 0 {
		return newValidationError("policy.allowed_hosts", "must list at least one host")
	}
	if len(r.Policy.AllowedMethods) == 0 {
		return newValidationError("policy.allowed_methods", "must list at least one method")
	}
	if len(r.Policy.AllowedPathPatterns) == 0 {
		return newValidationError("policy.allowed_path_patterns", "must list at least one path pattern")
	}
	if len(r.Policy.HeaderTemplate) == 0 && len(r.Policy.QueryTemplate) == 0 {
		return newValidationError("policy.header_template", "header_template or query_template must not be empty")
	}
	if r.Policy.TargetHost == "" || r.Policy.TargetPath == "" || r.Policy.Method == "" {
		return newValidationError("policy.target", "host, path, and method must not be empty")
	}
	return validateCredentialPolicyEnvelope(r.Policy)
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
