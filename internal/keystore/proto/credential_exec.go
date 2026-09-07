// credential_exec.go — payload models for credential_exec_request, the MCP
// Credential Control Plane's decrypt-to-tool exec sink.
//
// The exec sink is the HTTP sink's sibling: the same sealed payload (iv /
// ciphertext / aad, opened under the raw Group DEK behind the opaque handle or
// under the device-wrapped personal DEK), the same {{secret.<key>}} placeholder
// discipline, the same server-signed policy verified inside the Keeper. Only the
// destination differs — instead of a single HTTPS request, the decrypted
// credential is placed in the environment of one child process.
//
// What the signature binds is therefore different too. HTTP policies pin a
// network target (host / path / method); an exec policy has no such target,
// because a child process that has read the environment can go anywhere. So the
// signature binds the *command*: the absolute executable, the entire argv, and
// the working directory — the exact bytes a human approved. Anything else and no
// process is started (Validate below, then the handler re-checks against the
// verified policy).
//
// No raw secret is present in either direction: env_template values are
// placeholders resolved against the decrypted payload inside the Keeper, and the
// response carries only capped, redacted output.

package proto

// CredentialExecRequest is the exec-direction decrypt-to-tool request.
// RequestID correlation is carried by the BaseRequest envelope, so it is not
// duplicated here.
type CredentialExecRequest struct {
	// Exactly one key source, identical to CredentialHTTPRequest. GroupHandle
	// opens an org-scope sealed payload. EncryptedDEKB64 opens an explicitly
	// supplied device-wrapped personal DEK. UseLocalPersonalDEK reads that
	// wrapped value from the Keeper Keychain, so MCP does not receive key
	// material.
	GroupHandle         string `json:"group_handle,omitempty"`
	EncryptedDEKB64     string `json:"encrypted_dek_b64,omitempty"`
	UseLocalPersonalDEK bool   `json:"use_local_personal_dek,omitempty"`
	IVB64               string `json:"iv_b64"`         // 12B IV, public material
	CiphertextB64       string `json:"ciphertext_b64"` // sealed payload (public material)
	AADB64              string `json:"aad_b64"`        // canonical AAD, opened byte-identically (public material)

	// Executable is an absolute path. The Keeper never performs a PATH lookup —
	// resolving a name to a path happens in the untrusted caller, and the check
	// that matters is whether the resolved path is the one the human approved
	// and the server signed.
	Executable string `json:"executable"`
	// Args is argv[1:]. argv[0] is always Executable; there is no shell, so no
	// field here is ever parsed as one.
	Args []string `json:"args,omitempty"`
	// Cwd is an absolute path that must exist as a directory. It is required
	// because the Keeper's own working directory is whatever Chrome or the MCP
	// process left behind and means nothing to the command.
	Cwd string `json:"cwd"`
	// EnvTemplate maps environment variable name to a value carrying only
	// {{secret.<key>}} placeholders, e.g. {"GH_TOKEN":"{{secret.token}}"};
	// the raw secret never appears here. Resolved against the decrypted
	// payload's secret map inside the Keeper.
	EnvTemplate map[string]string `json:"env_template"`

	Policy CredentialPolicy `json:"policy"`
}

func (r CredentialExecRequest) Validate() error {
	if err := validateCredentialKeySource(r.GroupHandle, r.EncryptedDEKB64, r.UseLocalPersonalDEK); err != nil {
		return err
	}
	if err := validateCredentialSealedPayload(r.IVB64, r.CiphertextB64, r.AADB64); err != nil {
		return err
	}
	// The whole point of the action is to inject the decrypted secret into the
	// child's environment, so an empty template has no legitimate caller — the
	// process would start without the credential.
	if len(r.EnvTemplate) == 0 {
		return newValidationError("env_template", "must not be empty")
	}
	// An exec policy is an env policy. A signed policy that also carries a
	// header or query template is an HTTP policy being pointed at the wrong
	// sink, and the two enforce different things — refuse rather than run the
	// half that applies.
	if len(r.Policy.HeaderTemplate) > 0 {
		return newValidationError("policy.header_template", "must be empty for an exec request")
	}
	if len(r.Policy.QueryTemplate) > 0 {
		return newValidationError("policy.query_template", "must be empty for an exec request")
	}
	if err := requireAbsoluteExecPath(r.Executable, "executable"); err != nil {
		return err
	}
	if err := requireAbsoluteExecPath(r.Cwd, "cwd"); err != nil {
		return err
	}
	for _, arg := range r.Args {
		if containsNUL(arg) {
			return newValidationError("args", "must not contain NUL")
		}
	}
	// The command is only ever the one the server signed. Comparing here, before
	// the payload is opened, means a mismatched request never reaches the
	// decrypt — let alone the spawn.
	//
	// All four refusals carry the identical reason, so the whole class is one
	// stable string for a caller to key on: error_code "validation_error" with a
	// message ending in credentialExecMismatchReason. The field name says which
	// half differed, for a human reading a log.
	if r.Executable != r.Policy.ExecExecutable {
		return newValidationError("executable", credentialExecMismatchReason)
	}
	if !CredentialExecArgvEqual(append([]string{r.Executable}, r.Args...), r.Policy.ExecArgv) {
		return newValidationError("args", credentialExecMismatchReason)
	}
	if r.Cwd != r.Policy.ExecCwd {
		return newValidationError("cwd", credentialExecMismatchReason)
	}
	if !CredentialTemplatesEqual(r.EnvTemplate, r.Policy.EnvTemplate) {
		return newValidationError("env_template", credentialExecMismatchReason)
	}
	return validateCredentialPolicyEnvelope(r.Policy)
}

// credentialExecMismatchReason is the one reason string every "the request is
// not the command the server signed" refusal carries. It is part of the action's
// contract, not just prose: a caller distinguishes "policy refused this" from
// "the process failed" by error_code "validation_error" plus this suffix, the
// same way credential_http_request's "request target does not match signed
// execution target" is matched today. Do not reword it without updating
// docs/protocol.md and the callers that classify it.
const credentialExecMismatchReason = "does not match signed credential policy"

// requireAbsoluteExecPath rejects an empty, relative, over-long, or NUL-bearing
// path. Absolute means a leading "/" — the same rule the server applies, spelled
// the same way on both sides so a path can never be absolute to one and relative
// to the other. credential_exec_request is refused outright on Windows, so there
// is no drive-letter form to accept here.
func requireAbsoluteExecPath(value, field string) error {
	if value == "" {
		return newValidationError(field, "must not be empty")
	}
	if value[0] != '/' {
		return newValidationError(field, "must be an absolute path")
	}
	if len(value) > credentialExecPathMaxLen {
		return newValidationError(field, "is too long")
	}
	if containsNUL(value) {
		return newValidationError(field, "must not contain NUL")
	}
	return nil
}

// credentialExecPathMaxLen matches the server's exec_executable / exec_cwd
// column width, so a path the server can store is a path the Keeper accepts.
const credentialExecPathMaxLen = 1024

func containsNUL(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == 0 {
			return true
		}
	}
	return false
}

// CredentialExecResponseData is the capped, redacted result of the child
// process. It never carries the plaintext credential: any echo of the injected
// value in either stream is masked before Base64 encoding.
//
// ExitCode is data, not an error — a command that exits non-zero returns a
// successful response carrying that code, the same way an HTTP 401 is a
// successful credential_http_request. The one exception is TimedOut, which
// reports ExitCode -1 because the process never got to choose one.
type CredentialExecResponseData struct {
	ExitCode  int    `json:"exit_code"`
	StdoutB64 string `json:"stdout_b64"` // redacted stdout, Base64
	StderrB64 string `json:"stderr_b64"` // redacted stderr, Base64
	Truncated bool   `json:"truncated"`  // true when either stream hit its cap
	TimedOut  bool   `json:"timed_out"`  // true when the process group was killed on timeout
}
