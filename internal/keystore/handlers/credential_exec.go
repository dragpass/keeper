// credential_exec.go — the credential_exec_request handler: the Keeper's
// decrypt-to-tool exec sink for the MCP Credential Control Plane (0.0.28).
//
// This is the Keeper's first process-spawning surface. The shape mirrors
// credential_http.go exactly — open the sealed payload under the key behind the
// handle, verify the server-signed policy, substitute {{secret.<key>}}
// placeholders, use the credential, redact and return — and every step it shares
// with the HTTP sink runs the same code, because two copies of a security sink
// are two things to keep in step and one of them always falls behind.
//
// What is genuinely different is what the signature binds. An HTTP policy pins a
// network target: allowed_hosts exact-match is what keeps the credential from
// going somewhere else. exec has no such thing. A child process that has read
// the environment can open any socket it likes, and the Keeper cannot stop it.
// So the boundary is not what the child does, it is which child runs: the signed
// policy carries the exact executable, argv and cwd a human approved, and
// anything else means no process starts.
//
// The in-Keeper safeguards, against the HTTP sink's numbering:
//  1. policy re-validation → executable / argv / cwd / env_template must equal
//     the verified policy exactly (checked in proto Validate before the payload
//     is opened, and again here against the signature-verified policy).
//  2. SSRF / private-IP blocking → NO COUNTERPART. Recorded, not mitigated.
//  3. HTTPS enforcement → no shell. The command is spawned by absolute path with
//     no PATH lookup, and no field of the request is ever parsed as a shell
//     string.
//  4. redirect blocking → a new process group, killed as a group on timeout, so
//     a grandchild cannot outlive the request holding the credential.
//  5. response size cap → 1 MiB per stream with a truncation flag.
//  6. timeout → 60s, a Keeper-owned constant the caller cannot widen.
//  7. response redaction → maskSecrets over stdout and stderr.
//  8. zeroize → the decrypted payload is zeroized; the assembled environment
//     strings are Go strings, so those are reference drops (the same limit, and
//     the same sentence, as the HTTP sink's wipeSecretStrings).
//  9. query rendering → replaced by the clean environment: the child inherits a
//     fixed allowlist plus the injected variable, never the caller's own
//     DRAGPASS_API_TOKEN.
//
// The secret goes into the environment and never into argv, deliberately:
// /proc/<pid>/cmdline is world-readable while /proc/<pid>/environ is not. That
// is the reason this sink is exec-with-env and not exec-with-args.

package handlers

import (
	"encoding/base64"
	"encoding/json"
	"os"

	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/secure"
)

// HandleCredentialExecRequest opens the sealed credential, injects it into the
// child's environment, runs the signed command, and returns the capped and
// redacted output.
func HandleCredentialExecRequest(d Deps, req proto.CredentialExecRequest) proto.BaseResponse {
	d.Logger.Println("credential exec request processing...")

	// Safeguard 4 (part): refuse the whole action where the process-group kill
	// does not exist, rather than run with a timeout that leaves grandchildren
	// alive. No fallback, silent or otherwise.
	if !credentialExecSupported {
		return errs.CodeResponse(errs.ErrCodeUnsupported,
			"credential_exec_request is not supported on this platform")
	}

	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}

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

	// Safeguard 1: re-check the command against the now-verified policy. Validate
	// compared the same fields, but it did so against a policy no one had checked
	// the signature of yet. This is the comparison that means "the command is the
	// one a human approved", and it stands between here and the spawn.
	if !execCommandMatchesPolicy(req) {
		return errs.CodeResponse(errs.ErrCodeValidation,
			"request command does not match signed credential policy")
	}
	if !envTemplatesEqual(req.EnvTemplate, req.Policy.EnvTemplate) {
		return errs.CodeResponse(errs.ErrCodeValidation,
			"env_template does not match signed credential policy")
	}
	// The Keeper's own working directory is whatever Chrome or the MCP process
	// left behind, so cwd is required — and it has to be a directory that exists,
	// or the spawn fails with a message that says nothing useful.
	if info, err := os.Stat(req.Cwd); err != nil || !info.IsDir() {
		return errs.CodeResponse(errs.ErrCodeValidation, "cwd is not an existing directory")
	}

	// Safeguard 8 (part): decrypt inside the session lock, keep the plaintext in
	// a local slice, and zeroize it on return. AAD mismatch (a swapped sealed
	// payload) fails the open here.
	var payload []byte
	var decErr error
	useErr := withCredentialDEK(d, credentialKeySource{
		groupHandle:         req.GroupHandle,
		encryptedDEKB64:     req.EncryptedDEKB64,
		useLocalPersonalDEK: req.UseLocalPersonalDEK,
	}, func(dek []byte) error {
		pt, err := AESGCMOpenWithAAD(dek, iv, ciphertext, aad)
		if err != nil {
			decErr = err
			return nil
		}
		payload = pt
		return nil
	})
	if useErr != nil {
		return sessionUseError(useErr, "credential exec request")
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

	variables, injected, err := substituteSecretEnv(req.EnvTemplate, cred.Secret)
	if err != nil {
		wipeSecretStrings(cred.Secret)
		return errs.CodeResponse(errs.ErrCodeValidation, err.Error())
	}

	// Safeguard 9: the child's environment is built, not inherited.
	env := cleanExecEnv(variables)

	result, runErr := runCredentialExec(req.Executable, req.Args, req.Cwd, env,
		defaultCredentialExecTimeout, defaultCredentialExecMaxStream)

	// Safeguard 8 (part): drop references to the assembled values and the parsed
	// secret map now that the child has them. (Go strings are immutable, so this
	// is a best-effort reference drop; the decrypted payload buffer above is the
	// byte slice that gets truly zeroized. env itself is a slice of "NAME=value"
	// strings with the same limit.)
	wipeSecretStrings(cred.Secret)
	wipeSecretStrings(variables)
	for i := range env {
		env[i] = ""
	}

	if runErr != nil {
		// A spawn failure is an error; a non-zero exit is not. Mask anyway — the
		// message is built from the executable and the OS error, but this is the
		// one path that could grow a new source of text later.
		return errs.CodeResponse(errs.ErrCodeInternal,
			maskSecrets("credential exec failed: "+runErr.Error(), injected))
	}

	// Safeguards 5 and 7: the streams are already capped; mask any echo of the
	// injected credential before it leaves the Keeper. A command that prints its
	// own token (gh auth token, say) shows the caller a masked value — that is
	// this sink's definition, not a bug.
	data := proto.CredentialExecResponseData{
		ExitCode:  result.ExitCode,
		StdoutB64: base64.StdEncoding.EncodeToString(redactBody(result.Stdout, injected)),
		StderrB64: base64.StdEncoding.EncodeToString(redactBody(result.Stderr, injected)),
		Truncated: result.Truncated,
		TimedOut:  result.TimedOut,
	}

	// The exit code is data, so the log line says nothing about success or
	// failure of the command itself — only that the sink ran.
	d.Logger.Println("credential exec request completed")
	return proto.BaseResponse{Success: true, Data: data}
}

// execCommandMatchesPolicy reports whether the request's executable, argv and
// cwd are exactly the signed ones.
func execCommandMatchesPolicy(req proto.CredentialExecRequest) bool {
	return req.Executable == req.Policy.ExecExecutable &&
		req.Cwd == req.Policy.ExecCwd &&
		proto.CredentialExecArgvEqual(
			append([]string{req.Executable}, req.Args...), req.Policy.ExecArgv)
}
