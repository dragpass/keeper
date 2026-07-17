// actions_credential.go — Wire-protocol Action* constant for the MCP Credential
// Control Plane's decrypt-to-tool HTTP action.
//
// Split out of actions_group_dek.go for domain locality: credential_http_request
// is the Keeper's first network surface and its own security domain (policy
// enforcement, SSRF blocking, TLS, redirect blocking, response redaction), so it
// keeps its own actions_*/registry_* fragment pair rather than riding on the
// Group DEK catalog.

package proto

const (
	// CredentialHTTPRequest: decrypt-to-tool. The Keeper opens a sealed
	// credential payload (AES-GCM under the raw Group DEK behind the opaque
	// handle, AAD-bound like group_encrypt_with_aad), substitutes the decrypted
	// secret into the caller-supplied header template, performs the outbound
	// HTTPS request, and returns a redacted response. The plaintext credential
	// is assembled, used, and zeroized entirely inside the Keeper — it never
	// crosses the IPC boundary into the MCP / AI process, in the request, the
	// response, or the logs (the same decrypt-to-sink discipline as
	// group_decrypt_to_clipboard, extended to an HTTP sink).
	//
	//   Inputs: group_handle, iv_b64(12B), ciphertext_b64, aad_b64,
	//           target_url, method, header_template (placeholders only:
	//           {"Authorization":"Bearer {{secret.token}}"}), body_b64?, policy
	//   Output: {status_code, headers(redacted), body_b64(redacted), truncated}
	//
	// In-Keeper enforcement (each a distinct safeguard, see handlers/
	// credential_http.go + credential_http_safety.go): (1) policy re-validation
	// (target host exact-match against policy.allowed_hosts, method allowlist),
	// (2) SSRF / private-IP blocking with a connect-time Dialer.Control hook that
	// re-checks the resolved IP (DNS-rebinding / TOCTOU safe), (3) HTTPS-only with
	// TLS verification on, (4) all redirects blocked, (5) response size cap with a
	// truncation flag, (6) request timeout, (7) response redaction (Authorization /
	// Set-Cookie / Proxy-Authorization headers stripped, injected secret masked if
	// echoed in the body), (8) decrypted payload + assembled headers zeroized right
	// after use.
	//
	// header_template values carry only {{secret.<key>}} placeholders resolved
	// against the decrypted payload's secret map — no raw secret is ever supplied
	// in the request.
	ActionCredentialHTTPRequest = "credential_http_request"
)
