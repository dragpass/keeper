// credential_exec_test.go — the platform-independent half of the
// credential_exec_request guards: the pure helpers and the shared fixtures.
//
// The exec sink only exists where a process group can be killed as one, so
// everything that actually spawns a child lives in credential_exec_unix_test.go
// (build-tagged !windows) and the refusal on the platform without that primitive
// lives in credential_exec_windows_test.go. What stays here compiles and runs
// everywhere: the environment allowlist, which is pure map and os.LookupEnv
// work, and the request / policy builders both halves share.

package handlers

import (
	"strings"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/proto"
)

const credExecSecret = "SUPER_SECRET_TOKEN_XYZ"

// credExecTestPolicy — an exec policy binding exactly this command. HTTP lists
// and templates are empty, which is what makes it an exec policy.
func credExecTestPolicy(executable string, args []string, cwd string, env map[string]string) proto.CredentialPolicy {
	return proto.CredentialPolicy{
		EntryID:          "entry_3",
		DekVersion:       1,
		HeaderTemplate:   map[string]string{},
		ExecExecutable:   executable,
		ExecArgv:         append([]string{executable}, args...),
		ExecCwd:          cwd,
		EnvTemplate:      env,
		ApprovalMode:     "always_ask",
		Expiry:           "2100-01-01T00:00:00Z",
		Signature:        "test-signature",
		ServerKeyVersion: 1,
		SignatureAlg:     credentialPolicySignatureAlg,
	}
}

func credExecEnvTemplate() map[string]string {
	return map[string]string{"GH_TOKEN": "{{secret.token}}"}
}

// credExecRequest builds a well-formed request whose policy matches it. mutate
// breaks exactly one thing so a test can name what it is checking.
func credExecRequest(
	t *testing.T, groupRaw []byte, handle string,
	executable string, args []string, cwd string,
	mutate func(*proto.CredentialExecRequest),
) proto.CredentialExecRequest {
	t.Helper()
	credJSON := `{"type":"api_token","label":"t","secret":{"authorization_scheme":"Bearer","token":"` +
		credExecSecret + `"}}`
	ivB64, ctB64, aadB64 := sealCredentialForTest(t, groupRaw, credJSON, credTestAAD)
	req := proto.CredentialExecRequest{
		GroupHandle:   handle,
		IVB64:         ivB64,
		CiphertextB64: ctB64,
		AADB64:        aadB64,
		Executable:    executable,
		Args:          args,
		Cwd:           cwd,
		EnvTemplate:   credExecEnvTemplate(),
		Policy:        credExecTestPolicy(executable, args, cwd, credExecEnvTemplate()),
	}
	if mutate != nil {
		mutate(&req)
	}
	return req
}

// TestCleanExecEnv_AllowlistOnly — safeguard 9 at the unit level: the caller's
// own DRAGPASS_API_TOKEN is not in the environment the child receives, and an
// injected name that collides with the allowlist appears exactly once.
func TestCleanExecEnv_AllowlistOnly(t *testing.T) {
	t.Setenv("DRAGPASS_API_TOKEN", "parent-service-token")
	t.Setenv("HOME", "/home/tester")
	t.Setenv("SOME_OTHER_VAR", "leak-me")

	env := cleanExecEnv(map[string]string{"GH_TOKEN": credExecSecret})

	allowed := map[string]bool{"GH_TOKEN": true}
	for _, name := range credentialExecEnvAllowlist {
		allowed[name] = true
	}
	seen := map[string]int{}
	for _, entry := range env {
		name, _, found := strings.Cut(entry, "=")
		if !found {
			t.Fatalf("environment entry has no '=': %q", entry)
		}
		seen[name]++
		if !allowed[name] {
			t.Errorf("child environment carries %q, which is not on the allowlist", name)
		}
	}
	if seen["DRAGPASS_API_TOKEN"] != 0 {
		t.Error("the caller's DRAGPASS_API_TOKEN reached the child")
	}
	if seen["SOME_OTHER_VAR"] != 0 {
		t.Error("an unlisted parent variable reached the child")
	}
	if seen["GH_TOKEN"] != 1 {
		t.Errorf("GH_TOKEN appears %d times, want exactly 1", seen["GH_TOKEN"])
	}

	// A collision replaces rather than duplicates.
	collide := cleanExecEnv(map[string]string{"HOME": "/injected"})
	homes := 0
	for _, entry := range collide {
		if strings.HasPrefix(entry, "HOME=") {
			homes++
			if entry != "HOME=/injected" {
				t.Errorf("HOME = %q, want the injected value to win", entry)
			}
		}
	}
	if homes != 1 {
		t.Errorf("HOME appears %d times, want exactly 1", homes)
	}
}
