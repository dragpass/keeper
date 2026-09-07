// actions_credential.go — Wire-protocol Action* constant for the MCP Credential
// Control Plane's decrypt-to-tool HTTP action.
//
// Split out of actions_group_dek.go for domain locality: credential_http_request
// is the Keeper's first network surface and its own security domain (policy
// enforcement, SSRF blocking, TLS, redirect blocking, response redaction), so it
// keeps its own actions_*/registry_* fragment pair rather than riding on the
// Group DEK catalog. credential_exec_request joined it as the second sink:
// same sealed payload, same signed policy, a local child process instead of an
// outbound request.

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

	// CredentialExecRequest: decrypt-to-tool, exec sink (0.0.28). The Keeper
	// opens the same sealed credential payload credential_http_request opens,
	// substitutes the decrypted secret into the caller-supplied environment
	// template, runs one child process, and returns its capped and redacted
	// output. The plaintext credential is assembled, used, and dropped entirely
	// inside the Keeper and the child's environment — it never crosses the IPC
	// boundary into the MCP / AI process, in the request, the response, or the
	// logs.
	//
	//   Inputs: group_handle | encrypted_dek_b64 | use_local_personal_dek,
	//           iv_b64(12B), ciphertext_b64, aad_b64,
	//           executable (absolute path), args (argv[1:]), cwd (absolute),
	//           env_template (placeholders only:
	//           {"GH_TOKEN":"{{secret.token}}"}), policy
	//   Output: {exit_code, stdout_b64(redacted), stderr_b64(redacted),
	//           truncated, timed_out}
	//
	// In-Keeper enforcement (see handlers/credential_exec.go +
	// credential_exec_safety.go): (1) the signed policy's exec_executable /
	// exec_argv / exec_cwd / env_template must equal the request exactly, or no
	// process is started, (2) no shell — the executable is spawned by absolute
	// path with no PATH lookup and there is no shell-string field anywhere in
	// the request, (3) a clean environment built from a fixed allowlist plus the
	// injected variable, so the caller's own DRAGPASS_API_TOKEN cannot reach the
	// child, (4) the secret goes to the environment and never to argv
	// (/proc/<pid>/cmdline is world-readable; the environment is not), (5) a new
	// process group killed as a group on timeout, so a sleeping grandchild dies
	// with its parent, (6) a Keeper-owned 60s timeout the caller cannot widen,
	// (7) a 1 MiB cap per stream with a truncation flag, (8) stdout / stderr
	// redaction of any echoed secret, (9) the decrypted payload zeroized after
	// use.
	//
	// What it does NOT do, deliberately: nothing constrains where the child goes
	// once it has read the environment. The HTTP sink's allowed_hosts has no
	// counterpart here — command-level approval is the whole mitigation.
	// Unsupported on Windows, where a process group cannot be killed as one.
	ActionCredentialExecRequest = "credential_exec_request"
)
