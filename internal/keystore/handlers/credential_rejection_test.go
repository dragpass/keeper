// credential_rejection_test.go — the rejection-stage golden for both credential
// sinks.
//
// The two decrypt-to-tool handlers run the same prelude in the same order:
// Validate → key source → open the AAD-bound sealed payload under the DEK →
// verify the signed policy → check the request against that policy →
// substitute the {{secret.<key>}} templates → hand the secret to the sink. Which
// stage refuses first is a contract, not an implementation detail: a caller
// classifies "policy refused this" against "the tool failed" by error_code plus
// the message, and reordering two checks silently changes the answer for a
// request that fails both.
//
// So each table row breaks exactly one thing and pins the exact error_code and
// message that comes back. The rows are listed in the order the handler reaches
// them, which makes the table readable as the pipeline itself.
//
// Every row also asserts the sealed secret reached neither the response nor the
// log — the rows past the decrypt are the ones where that could regress.
//
// The Windows platform gate (the exec sink refuses before it touches anything)
// is pinned in credential_exec_windows_test.go, so this file skips the exec half
// where the sink does not exist.

package handlers

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/logger"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// credRejectHost — no row here is supposed to reach the network, but a check
// that stops firing is exactly how one would. ".invalid" never resolves (RFC
// 2606), so such a regression fails instead of dialing out.
const credRejectHost = "api.dragpass.invalid"

const credRejectSecret = "SUPER_SECRET_TOKEN_XYZ"

const credRejectPayload = `{"type":"api_token","label":"t","secret":{"token":"` + credRejectSecret + `"}}`

// credRejectAADOtherScope passes the policy binding check (entry_id /
// payload_kind / schema_version / dek_version all match) but is not the AAD the
// payload was sealed under, because the scope slot differs. It is how a row
// reaches the AEAD open and fails *there* rather than at the binding check.
const credRejectAADOtherScope = "org_OTHER|entry_3|credential|1|1"

// credRejectExecutable is absolute (so Validate accepts it) and does not exist,
// so a row that wrongly got past every check would fail to spawn rather than run
// something.
const credRejectExecutable = "/nonexistent/dragpass-credential-rejection"

var errCredRejectSignature = errors.New("server signature mismatch")

// assertCredRejection pins the refusal: never a success, the exact error_code
// and message, and no trace of the sealed secret in either output surface.
func assertCredRejection(t *testing.T, resp proto.BaseResponse, log *logger.MemoryLogger,
	wantCode errs.ErrorCode, wantError string) {
	t.Helper()
	if resp.Success {
		t.Fatalf("expected a refusal, got success")
	}
	if resp.ErrorCode != string(wantCode) {
		t.Fatalf("error_code = %q, want %q (message was %q)", resp.ErrorCode, wantCode, resp.Error)
	}
	if resp.Error != wantError {
		t.Fatalf("error = %q, want %q", resp.Error, wantError)
	}
	respJSON, _ := json.Marshal(resp)
	if strings.Contains(string(respJSON), credRejectSecret) {
		t.Fatalf("the refusal leaked the sealed secret: %s", respJSON)
	}
	if log.Contains(credRejectSecret) {
		t.Fatalf("the refusal leaked the sealed secret into the log: %v", log.Messages())
	}
}

// credRejectHTTPRequest builds a request every check accepts. Each row breaks
// one thing in it.
func credRejectHTTPRequest(t *testing.T, groupRaw []byte, handle string) proto.CredentialHTTPRequest {
	t.Helper()
	ivB64, ctB64, aadB64 := sealCredentialForTest(t, groupRaw, credRejectPayload, credTestAAD)
	return proto.CredentialHTTPRequest{
		GroupHandle:    handle,
		IVB64:          ivB64,
		CiphertextB64:  ctB64,
		AADB64:         aadB64,
		TargetURL:      "https://" + credRejectHost + "/x",
		Method:         "GET",
		HeaderTemplate: map[string]string{"Authorization": "Bearer {{secret.token}}"},
		Policy:         credTestPolicy([]string{credRejectHost}, []string{"GET"}),
	}
}

func TestCredentialHTTP_RejectionStagesAreStable(t *testing.T) {
	cases := []struct {
		stage      string
		failVerify bool
		mutate     func(t *testing.T, groupRaw []byte, r *proto.CredentialHTTPRequest)
		wantCode   errs.ErrorCode
		wantError  string
	}{
		{
			stage:     "no key source",
			mutate:    func(_ *testing.T, _ []byte, r *proto.CredentialHTTPRequest) { r.GroupHandle = "" },
			wantCode:  errs.ErrCodeValidation,
			wantError: "group_handle: exactly one key source is required",
		},
		{
			stage: "iv is not 12 bytes",
			mutate: func(_ *testing.T, _ []byte, r *proto.CredentialHTTPRequest) {
				r.IVB64 = base64.StdEncoding.EncodeToString(make([]byte, 11))
			},
			wantCode:  errs.ErrCodeValidation,
			wantError: "iv_b64: decoded length must be 12 bytes, got 11",
		},
		{
			stage:     "ciphertext is not Base64",
			mutate:    func(_ *testing.T, _ []byte, r *proto.CredentialHTTPRequest) { r.CiphertextB64 = "not base64!!" },
			wantCode:  errs.ErrCodeValidation,
			wantError: "ciphertext_b64: must be valid Base64",
		},
		{
			stage:     "aad is missing",
			mutate:    func(_ *testing.T, _ []byte, r *proto.CredentialHTTPRequest) { r.AADB64 = "" },
			wantCode:  errs.ErrCodeValidation,
			wantError: "aad_b64: must not be empty",
		},
		{
			stage: "target_url is not https",
			mutate: func(_ *testing.T, _ []byte, r *proto.CredentialHTTPRequest) {
				r.TargetURL = "http://" + credRejectHost + "/x"
			},
			wantCode:  errs.ErrCodeValidation,
			wantError: "target_url must use https",
		},
		{
			stage: "unsupported policy signature algorithm",
			mutate: func(_ *testing.T, _ []byte, r *proto.CredentialHTTPRequest) {
				r.Policy.SignatureAlg = "rsa-pkcs1-sha256"
			},
			wantCode:  errs.ErrCodeValidation,
			wantError: "unsupported credential policy signature algorithm",
		},
		{
			stage:     "policy expiry is unparseable",
			mutate:    func(_ *testing.T, _ []byte, r *proto.CredentialHTTPRequest) { r.Policy.Expiry = "not-a-time" },
			wantCode:  errs.ErrCodeValidation,
			wantError: "credential policy expiry is invalid",
		},
		{
			stage:     "policy has expired",
			mutate:    func(_ *testing.T, _ []byte, r *proto.CredentialHTTPRequest) { r.Policy.Expiry = "2000-01-01T00:00:00Z" },
			wantCode:  errs.ErrCodeCryptoFailure,
			wantError: "credential policy has expired",
		},
		{
			stage:     "policy entry_id is not the AAD's",
			mutate:    func(_ *testing.T, _ []byte, r *proto.CredentialHTTPRequest) { r.Policy.EntryID = "entry_other" },
			wantCode:  errs.ErrCodeCryptoFailure,
			wantError: "credential policy entry_id does not match AAD",
		},
		{
			stage:      "server signature does not verify",
			failVerify: true,
			wantCode:   errs.ErrCodeCryptoFailure,
			wantError:  errCredRejectSignature.Error(),
		},
		{
			stage:     "request target is not the signed one",
			mutate:    func(_ *testing.T, _ []byte, r *proto.CredentialHTTPRequest) { r.Policy.TargetPath = "/y" },
			wantCode:  errs.ErrCodeValidation,
			wantError: "request target does not match signed execution target",
		},
		{
			stage: "host is not in allowed_hosts",
			mutate: func(_ *testing.T, _ []byte, r *proto.CredentialHTTPRequest) {
				r.Policy.AllowedHosts = []string{"other.invalid"}
			},
			wantCode:  errs.ErrCodeValidation,
			wantError: "target host is not in policy.allowed_hosts",
		},
		{
			stage: "method is not in allowed_methods",
			mutate: func(_ *testing.T, _ []byte, r *proto.CredentialHTTPRequest) {
				r.Policy.AllowedMethods = []string{"POST"}
			},
			wantCode:  errs.ErrCodeValidation,
			wantError: "method is not in policy.allowed_methods",
		},
		{
			stage: "path is not in allowed_path_patterns",
			mutate: func(_ *testing.T, _ []byte, r *proto.CredentialHTTPRequest) {
				r.Policy.AllowedPathPatterns = []string{"/z"}
			},
			wantCode:  errs.ErrCodeValidation,
			wantError: "target path is not in policy.allowed_path_patterns",
		},
		{
			stage:     "query is not allowed by the policy",
			mutate:    func(_ *testing.T, _ []byte, r *proto.CredentialHTTPRequest) { r.TargetURL += "?a=b" },
			wantCode:  errs.ErrCodeValidation,
			wantError: "query or body is not allowed by credential policy",
		},
		{
			stage: "header_template is not the signed one",
			mutate: func(_ *testing.T, _ []byte, r *proto.CredentialHTTPRequest) {
				r.Policy.HeaderTemplate = map[string]string{"Authorization": "Bearer {{secret.other}}"}
			},
			wantCode:  errs.ErrCodeValidation,
			wantError: "header_template does not match signed credential policy",
		},
		{
			stage: "query_template is not the signed one",
			mutate: func(_ *testing.T, _ []byte, r *proto.CredentialHTTPRequest) {
				r.QueryTemplate = map[string]string{"api_key": "{{secret.token}}"}
			},
			wantCode:  errs.ErrCodeValidation,
			wantError: "query_template does not match signed credential policy",
		},
		{
			stage: "body is not Base64",
			mutate: func(_ *testing.T, _ []byte, r *proto.CredentialHTTPRequest) {
				r.BodyB64 = "!!!"
				r.Policy.AllowBody = true
			},
			wantCode:  errs.ErrCodeValidation,
			wantError: "failed to decode body_b64: illegal base64 data at input byte 0",
		},
		{
			stage: "sealed payload was sealed under another AAD",
			mutate: func(_ *testing.T, _ []byte, r *proto.CredentialHTTPRequest) {
				r.AADB64 = base64.StdEncoding.EncodeToString([]byte(credRejectAADOtherScope))
			},
			wantCode:  errs.ErrCodeCryptoFailure,
			wantError: "sealed payload decrypt failed",
		},
		{
			stage: "sealed payload is not a credential",
			mutate: func(t *testing.T, groupRaw []byte, r *proto.CredentialHTTPRequest) {
				r.IVB64, r.CiphertextB64, r.AADB64 = sealCredentialForTest(t, groupRaw, "not-json", credTestAAD)
			},
			wantCode:  errs.ErrCodeCryptoFailure,
			wantError: "sealed payload is not a valid credential",
		},
		{
			stage: "header_template names a key the payload lacks",
			mutate: func(_ *testing.T, _ []byte, r *proto.CredentialHTTPRequest) {
				tmpl := map[string]string{"Authorization": "Bearer {{secret.nope}}"}
				r.HeaderTemplate = tmpl
				r.Policy.HeaderTemplate = tmpl
			},
			wantCode:  errs.ErrCodeValidation,
			wantError: `header_template references unknown secret key "nope"`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.stage, func(t *testing.T) {
			deps, log, _ := newTestDeps(t)
			if tc.failVerify {
				deps, log, _ = newTestDepsFailVerify(t, errCredRejectSignature)
			}
			handle, groupRaw := openSessionForFreshKey(t, deps)
			req := credRejectHTTPRequest(t, groupRaw, handle)
			if tc.mutate != nil {
				tc.mutate(t, groupRaw, &req)
			}
			assertCredRejection(t, HandleCredentialHTTPRequest(deps, req), log, tc.wantCode, tc.wantError)
		})
	}
}

// credRejectExecRequest builds an exec request every check accepts, other than
// actually finding the executable — no row here gets that far.
func credRejectExecRequest(t *testing.T, groupRaw []byte, handle, cwd string) proto.CredentialExecRequest {
	t.Helper()
	ivB64, ctB64, aadB64 := sealCredentialForTest(t, groupRaw, credRejectPayload, credTestAAD)
	envTemplate := map[string]string{"GH_TOKEN": "{{secret.token}}"}
	return proto.CredentialExecRequest{
		GroupHandle:   handle,
		IVB64:         ivB64,
		CiphertextB64: ctB64,
		AADB64:        aadB64,
		Executable:    credRejectExecutable,
		Cwd:           cwd,
		EnvTemplate:   envTemplate,
		Policy:        credExecTestPolicy(credRejectExecutable, nil, cwd, envTemplate),
	}
}

func TestCredentialExec_RejectionStagesAreStable(t *testing.T) {
	if !credentialExecSupported {
		t.Skip("the exec sink is refused outright here; credential_exec_windows_test.go covers that")
	}

	cases := []struct {
		stage      string
		failVerify bool
		mutate     func(t *testing.T, groupRaw []byte, r *proto.CredentialExecRequest)
		wantCode   errs.ErrorCode
		wantError  string
	}{
		{
			stage:     "no key source",
			mutate:    func(_ *testing.T, _ []byte, r *proto.CredentialExecRequest) { r.GroupHandle = "" },
			wantCode:  errs.ErrCodeValidation,
			wantError: "group_handle: exactly one key source is required",
		},
		{
			stage: "iv is not 12 bytes",
			mutate: func(_ *testing.T, _ []byte, r *proto.CredentialExecRequest) {
				r.IVB64 = base64.StdEncoding.EncodeToString(make([]byte, 11))
			},
			wantCode:  errs.ErrCodeValidation,
			wantError: "iv_b64: decoded length must be 12 bytes, got 11",
		},
		{
			stage:     "ciphertext is not Base64",
			mutate:    func(_ *testing.T, _ []byte, r *proto.CredentialExecRequest) { r.CiphertextB64 = "not base64!!" },
			wantCode:  errs.ErrCodeValidation,
			wantError: "ciphertext_b64: must be valid Base64",
		},
		{
			stage:     "aad is missing",
			mutate:    func(_ *testing.T, _ []byte, r *proto.CredentialExecRequest) { r.AADB64 = "" },
			wantCode:  errs.ErrCodeValidation,
			wantError: "aad_b64: must not be empty",
		},
		{
			stage:     "env_template is empty",
			mutate:    func(_ *testing.T, _ []byte, r *proto.CredentialExecRequest) { r.EnvTemplate = map[string]string{} },
			wantCode:  errs.ErrCodeValidation,
			wantError: "env_template: must not be empty",
		},
		{
			stage: "policy carries a header template",
			mutate: func(_ *testing.T, _ []byte, r *proto.CredentialExecRequest) {
				r.Policy.HeaderTemplate = map[string]string{"Authorization": "Bearer {{secret.token}}"}
			},
			wantCode:  errs.ErrCodeValidation,
			wantError: "policy.header_template: must be empty for an exec request",
		},
		{
			stage:     "executable is relative",
			mutate:    func(_ *testing.T, _ []byte, r *proto.CredentialExecRequest) { r.Executable = "gh" },
			wantCode:  errs.ErrCodeValidation,
			wantError: "executable: must be an absolute path",
		},
		{
			stage:     "executable is not the signed one",
			mutate:    func(_ *testing.T, _ []byte, r *proto.CredentialExecRequest) { r.Policy.ExecExecutable = "/bin/cat" },
			wantCode:  errs.ErrCodeValidation,
			wantError: "executable: does not match signed credential policy",
		},
		{
			stage: "argv is not the signed one",
			mutate: func(_ *testing.T, _ []byte, r *proto.CredentialExecRequest) {
				r.Policy.ExecArgv = append(append([]string{}, r.Policy.ExecArgv...), "--extra")
			},
			wantCode:  errs.ErrCodeValidation,
			wantError: "args: does not match signed credential policy",
		},
		{
			stage:     "cwd is not the signed one",
			mutate:    func(_ *testing.T, _ []byte, r *proto.CredentialExecRequest) { r.Policy.ExecCwd = "/" },
			wantCode:  errs.ErrCodeValidation,
			wantError: "cwd: does not match signed credential policy",
		},
		{
			stage: "env_template is not the signed one",
			mutate: func(_ *testing.T, _ []byte, r *proto.CredentialExecRequest) {
				r.Policy.EnvTemplate = map[string]string{"OTHER": "{{secret.token}}"}
			},
			wantCode:  errs.ErrCodeValidation,
			wantError: "env_template: does not match signed credential policy",
		},
		{
			stage: "unsupported policy signature algorithm",
			mutate: func(_ *testing.T, _ []byte, r *proto.CredentialExecRequest) {
				r.Policy.SignatureAlg = "rsa-pkcs1-sha256"
			},
			wantCode:  errs.ErrCodeValidation,
			wantError: "unsupported credential policy signature algorithm",
		},
		{
			stage:     "policy expiry is unparseable",
			mutate:    func(_ *testing.T, _ []byte, r *proto.CredentialExecRequest) { r.Policy.Expiry = "not-a-time" },
			wantCode:  errs.ErrCodeValidation,
			wantError: "credential policy expiry is invalid",
		},
		{
			stage:     "policy has expired",
			mutate:    func(_ *testing.T, _ []byte, r *proto.CredentialExecRequest) { r.Policy.Expiry = "2000-01-01T00:00:00Z" },
			wantCode:  errs.ErrCodeCryptoFailure,
			wantError: "credential policy has expired",
		},
		{
			stage:     "policy entry_id is not the AAD's",
			mutate:    func(_ *testing.T, _ []byte, r *proto.CredentialExecRequest) { r.Policy.EntryID = "entry_other" },
			wantCode:  errs.ErrCodeCryptoFailure,
			wantError: "credential policy entry_id does not match AAD",
		},
		{
			stage:      "server signature does not verify",
			failVerify: true,
			wantCode:   errs.ErrCodeCryptoFailure,
			wantError:  errCredRejectSignature.Error(),
		},
		{
			stage: "cwd does not exist",
			mutate: func(_ *testing.T, _ []byte, r *proto.CredentialExecRequest) {
				r.Cwd += "/no-such-dir"
				r.Policy.ExecCwd = r.Cwd
			},
			wantCode:  errs.ErrCodeValidation,
			wantError: "cwd is not an existing directory",
		},
		{
			stage: "sealed payload was sealed under another AAD",
			mutate: func(_ *testing.T, _ []byte, r *proto.CredentialExecRequest) {
				r.AADB64 = base64.StdEncoding.EncodeToString([]byte(credRejectAADOtherScope))
			},
			wantCode:  errs.ErrCodeCryptoFailure,
			wantError: "sealed payload decrypt failed",
		},
		{
			stage: "sealed payload is not a credential",
			mutate: func(t *testing.T, groupRaw []byte, r *proto.CredentialExecRequest) {
				r.IVB64, r.CiphertextB64, r.AADB64 = sealCredentialForTest(t, groupRaw, "not-json", credTestAAD)
			},
			wantCode:  errs.ErrCodeCryptoFailure,
			wantError: "sealed payload is not a valid credential",
		},
		{
			stage: "env_template names a key the payload lacks",
			mutate: func(_ *testing.T, _ []byte, r *proto.CredentialExecRequest) {
				tmpl := map[string]string{"GH_TOKEN": "{{secret.nope}}"}
				r.EnvTemplate = tmpl
				r.Policy.EnvTemplate = tmpl
			},
			wantCode:  errs.ErrCodeValidation,
			wantError: `env_template references unknown secret key "nope"`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.stage, func(t *testing.T) {
			deps, log, _ := newTestDeps(t)
			if tc.failVerify {
				deps, log, _ = newTestDepsFailVerify(t, errCredRejectSignature)
			}
			handle, groupRaw := openSessionForFreshKey(t, deps)
			req := credRejectExecRequest(t, groupRaw, handle, t.TempDir())
			if tc.mutate != nil {
				tc.mutate(t, groupRaw, &req)
			}
			assertCredRejection(t, HandleCredentialExecRequest(deps, req), log, tc.wantCode, tc.wantError)
		})
	}
}
