// credential_exec_test.go — HandleCredentialExecRequest guards.
//
// The exec sink's safeguards, each exercised on its own:
//   - safeguard 1: a request whose executable / argv / cwd differs from the
//     signed policy starts no process (proved by a fixture whose only job is to
//     leave a file behind — the file must not exist).
//   - safeguard 3: no shell and no PATH lookup — a relative executable is
//     refused outright.
//   - safeguard 4: the timeout kills the whole process group, so a grandchild
//     the child left sleeping dies with it.
//   - safeguard 5: each stream is capped and flagged.
//   - safeguard 7: a secret echoed on stdout or stderr comes back masked, and
//     the IPC response never carries it.
//   - safeguard 9: the child's environment is the fixed allowlist plus the
//     injected variable — the parent's DRAGPASS_API_TOKEN does not reach it.
//   - the secret is in the environment and never in argv.
//   - a non-zero exit is data: it rides back on a successful response.
//
// Fixtures use /bin/sh as the *target program*. That is a test choosing what to
// run, not production reaching for a shell: the handler spawns whatever absolute
// path the signature names and has no shell path of its own.

package handlers

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/dragpass/keeper/internal/keystore/logger"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

const credExecSecret = "SUPER_SECRET_TOKEN_XYZ"

// credExecFixtureShell returns an absolute /bin/sh, or skips. Every fixture here
// needs a program that can be told what to do through argv.
func credExecFixtureShell(t *testing.T) string {
	t.Helper()
	const sh = "/bin/sh"
	if info, err := os.Stat(sh); err != nil || info.IsDir() {
		t.Skipf("%s is not available", sh)
	}
	return sh
}

func credExecEnvBinary(t *testing.T) string {
	t.Helper()
	for _, candidate := range []string{"/usr/bin/env", "/bin/env"} {
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate
		}
	}
	t.Skip("no env(1) binary available")
	return ""
}

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

// credExecRoundTrip drives one full handler request.
func credExecRoundTrip(
	t *testing.T, executable string, args []string, cwd string,
	mutate func(*proto.CredentialExecRequest),
) (proto.CredentialExecResponseData, proto.BaseResponse, *logger.MemoryLogger) {
	t.Helper()
	deps, log, _ := newTestDeps(t)
	handle, groupRaw := openSessionForFreshKey(t, deps)
	req := credExecRequest(t, groupRaw, handle, executable, args, cwd, mutate)

	resp := HandleCredentialExecRequest(deps, req)
	if !resp.Success {
		return proto.CredentialExecResponseData{}, resp, log
	}
	data, ok := resp.Data.(proto.CredentialExecResponseData)
	if !ok {
		t.Fatalf("response data type = %T, want CredentialExecResponseData", resp.Data)
	}
	return data, resp, log
}

func decodeExecStream(t *testing.T, b64 string) string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("decode stream: %v", err)
	}
	return string(raw)
}

// TestCredentialExec_HappyPath_InjectsSecretIntoEnv — the child sees the secret
// in its environment (proved by its length, so the assertion itself does not
// echo it) and the IPC response carries no trace of it.
func TestCredentialExec_HappyPath_InjectsSecretIntoEnv(t *testing.T) {
	sh := credExecFixtureShell(t)
	args := []string{"-c", `printf "len=%s" "${#GH_TOKEN}"`}
	data, resp, log := credExecRoundTrip(t, sh, args, t.TempDir(), nil)
	if !resp.Success {
		t.Fatalf("expected success, got %s / %s", resp.Error, resp.ErrorCode)
	}
	if data.ExitCode != 0 {
		t.Fatalf("exit_code = %d, want 0", data.ExitCode)
	}
	want := "len=" + strconv.Itoa(len(credExecSecret))
	if got := decodeExecStream(t, data.StdoutB64); got != want {
		t.Fatalf("stdout = %q, want %q", got, want)
	}
	respJSON, _ := json.Marshal(resp)
	if strings.Contains(string(respJSON), credExecSecret) {
		t.Fatalf("IPC response leaked the injected secret: %s", respJSON)
	}
	if log.Contains(credExecSecret) {
		t.Fatal("logger leaked the injected secret")
	}
}

// TestCredentialExec_SecretIsMaskedInBothStreams — safeguard 7. A command that
// prints its own credential shows the caller a mask, on stdout and on stderr.
func TestCredentialExec_SecretIsMaskedInBothStreams(t *testing.T) {
	sh := credExecFixtureShell(t)
	args := []string{"-c", `printf "out:%s" "$GH_TOKEN"; printf "err:%s" "$GH_TOKEN" >&2`}
	data, resp, _ := credExecRoundTrip(t, sh, args, t.TempDir(), nil)
	if !resp.Success {
		t.Fatalf("expected success, got %s / %s", resp.Error, resp.ErrorCode)
	}
	stdout := decodeExecStream(t, data.StdoutB64)
	stderr := decodeExecStream(t, data.StderrB64)
	if strings.Contains(stdout, credExecSecret) || strings.Contains(stderr, credExecSecret) {
		t.Fatalf("secret survived redaction: stdout=%q stderr=%q", stdout, stderr)
	}
	if !strings.Contains(stdout, redactionMask) || !strings.Contains(stderr, redactionMask) {
		t.Fatalf("expected the mask in both streams: stdout=%q stderr=%q", stdout, stderr)
	}
}

// TestCredentialExec_NonZeroExitIsData — a failing command is a successful
// action. The exit code rides back the way an HTTP 401 does.
func TestCredentialExec_NonZeroExitIsData(t *testing.T) {
	sh := credExecFixtureShell(t)
	data, resp, _ := credExecRoundTrip(t, sh, []string{"-c", "exit 42"}, t.TempDir(), nil)
	if !resp.Success {
		t.Fatalf("non-zero exit must still be a success response: %s / %s", resp.Error, resp.ErrorCode)
	}
	if data.ExitCode != 42 {
		t.Fatalf("exit_code = %d, want 42", data.ExitCode)
	}
	if data.TimedOut {
		t.Fatal("timed_out must be false for a normal exit")
	}
}

// TestCredentialExec_SignedCommandMismatchStartsNoProcess — safeguard 1, one
// field at a time. The fixture's only job is to leave a file behind, so "no
// process started" is checked by the file's absence rather than by trusting the
// error message.
func TestCredentialExec_SignedCommandMismatchStartsNoProcess(t *testing.T) {
	sh := credExecFixtureShell(t)

	cases := []struct {
		name   string
		mutate func(*proto.CredentialExecRequest)
	}{
		{"executable", func(r *proto.CredentialExecRequest) {
			r.Policy.ExecExecutable = "/bin/cat"
		}},
		{"argv", func(r *proto.CredentialExecRequest) {
			r.Policy.ExecArgv = append(append([]string{}, r.Policy.ExecArgv...), "--extra")
		}},
		{"cwd", func(r *proto.CredentialExecRequest) {
			r.Policy.ExecCwd = "/"
		}},
		{"env_template", func(r *proto.CredentialExecRequest) {
			r.Policy.EnvTemplate = map[string]string{"OTHER": "{{secret.token}}"}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			marker := dir + "/ran"
			args := []string{"-c", "touch " + marker}
			_, resp, _ := credExecRoundTrip(t, sh, args, dir, tc.mutate)
			if resp.Success {
				t.Fatalf("mismatched %s was accepted", tc.name)
			}
			if _, err := os.Stat(marker); err == nil {
				t.Fatalf("a process ran despite the %s mismatch", tc.name)
			}
		})
	}
}

// TestCredentialExec_RejectsUnsafeShapes — Validate's structural refusals. Each
// one keeps a whole class of request from reaching the spawn.
func TestCredentialExec_RejectsUnsafeShapes(t *testing.T) {
	sh := credExecFixtureShell(t)
	dir := t.TempDir()

	cases := []struct {
		name   string
		mutate func(*proto.CredentialExecRequest)
	}{
		{"relative executable", func(r *proto.CredentialExecRequest) {
			r.Executable = "sh"
			r.Policy.ExecExecutable = "sh"
			r.Policy.ExecArgv = append([]string{"sh"}, r.Args...)
		}},
		{"relative cwd", func(r *proto.CredentialExecRequest) {
			r.Cwd = "relative/dir"
			r.Policy.ExecCwd = "relative/dir"
		}},
		{"NUL in an argument", func(r *proto.CredentialExecRequest) {
			r.Args = append(r.Args, "a\x00b")
			r.Policy.ExecArgv = append(append([]string{}, r.Policy.ExecArgv...), "a\x00b")
		}},
		{"empty env_template", func(r *proto.CredentialExecRequest) {
			r.EnvTemplate = map[string]string{}
			r.Policy.EnvTemplate = map[string]string{}
		}},
		{"policy carries a header template", func(r *proto.CredentialExecRequest) {
			r.Policy.HeaderTemplate = map[string]string{"Authorization": "Bearer {{secret.token}}"}
		}},
		{"policy carries a query template", func(r *proto.CredentialExecRequest) {
			r.Policy.QueryTemplate = map[string]string{"api_key": "{{secret.token}}"}
		}},
		{"unsigned policy", func(r *proto.CredentialExecRequest) {
			r.Policy.Signature = ""
		}},
		{"no key source", func(r *proto.CredentialExecRequest) {
			r.GroupHandle = ""
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			marker := t.TempDir() + "/ran"
			args := []string{"-c", "touch " + marker}
			_, resp, _ := credExecRoundTrip(t, sh, args, dir, tc.mutate)
			if resp.Success {
				t.Fatalf("%s was accepted", tc.name)
			}
			if _, err := os.Stat(marker); err == nil {
				t.Fatalf("a process ran despite %s", tc.name)
			}
		})
	}
}

// TestCredentialExec_RejectsMissingCwd — cwd has to exist as a directory. A
// spawn into a missing directory fails with an OS message that says nothing
// useful, so the refusal is explicit.
func TestCredentialExec_RejectsMissingCwd(t *testing.T) {
	sh := credExecFixtureShell(t)
	missing := t.TempDir() + "/no-such-dir"
	_, resp, _ := credExecRoundTrip(t, sh, []string{"-c", "true"}, missing, nil)
	if resp.Success {
		t.Fatal("a missing cwd was accepted")
	}
	if !strings.Contains(resp.Error, "cwd") {
		t.Fatalf("error = %q, want it to name cwd", resp.Error)
	}
}

// TestCredentialExec_UnknownSecretKeyStartsNoProcess — a placeholder naming a
// key the payload does not carry must not run the command with an empty
// credential in its environment.
func TestCredentialExec_UnknownSecretKeyStartsNoProcess(t *testing.T) {
	sh := credExecFixtureShell(t)
	dir := t.TempDir()
	marker := dir + "/ran"
	tmpl := map[string]string{"GH_TOKEN": "{{secret.nope}}"}
	_, resp, _ := credExecRoundTrip(t, sh, []string{"-c", "touch " + marker}, dir,
		func(r *proto.CredentialExecRequest) {
			r.EnvTemplate = tmpl
			r.Policy.EnvTemplate = tmpl
		})
	if resp.Success {
		t.Fatal("an unresolvable placeholder was accepted")
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("a process ran with an unresolved credential")
	}
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

// TestRunCredentialExec_ChildEnvironmentIsTheAllowlist — the same guarantee end
// to end: env(1) prints what it actually received.
func TestRunCredentialExec_ChildEnvironmentIsTheAllowlist(t *testing.T) {
	envBin := credExecEnvBinary(t)
	t.Setenv("DRAGPASS_API_TOKEN", "parent-service-token")

	env := cleanExecEnv(map[string]string{"GH_TOKEN": credExecSecret})
	result, err := runCredentialExec(envBin, nil, t.TempDir(), env, 10*time.Second, defaultCredentialExecMaxStream)
	if err != nil {
		t.Fatalf("runCredentialExec: %v", err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("exit_code = %d, want 0 (stderr: %s)", result.ExitCode, result.Stderr)
	}
	stdout := string(result.Stdout)
	if !strings.Contains(stdout, "GH_TOKEN="+credExecSecret) {
		t.Fatal("the child did not receive the injected variable")
	}
	if strings.Contains(stdout, "DRAGPASS_API_TOKEN") {
		t.Fatalf("the caller's service token reached the child: %q", stdout)
	}
	allowed := map[string]bool{"GH_TOKEN": true}
	for _, name := range credentialExecEnvAllowlist {
		allowed[name] = true
	}
	for _, line := range strings.Split(strings.TrimRight(stdout, "\n"), "\n") {
		if line == "" {
			continue
		}
		name, _, _ := strings.Cut(line, "=")
		if !allowed[name] {
			t.Errorf("child environment carries %q", name)
		}
	}
}

// TestRunCredentialExec_SecretIsNeverInArgv — the reason this sink is
// exec-with-env: /proc/<pid>/cmdline is world-readable and the environment is
// not. The child prints its own argv, and the credential is not in it.
func TestRunCredentialExec_SecretIsNeverInArgv(t *testing.T) {
	sh := credExecFixtureShell(t)
	args := []string{"-c", `printf "ARGV:"; for a in "$0" "$@"; do printf "[%s]" "$a"; done; printf " LEN:%s" "${#GH_TOKEN}"`}
	env := cleanExecEnv(map[string]string{"GH_TOKEN": credExecSecret})

	result, err := runCredentialExec(sh, args, t.TempDir(), env, 10*time.Second, defaultCredentialExecMaxStream)
	if err != nil {
		t.Fatalf("runCredentialExec: %v", err)
	}
	stdout := string(result.Stdout)
	if !strings.Contains(stdout, "LEN:"+strconv.Itoa(len(credExecSecret))) {
		t.Fatalf("the child did not see the credential in its environment: %q", stdout)
	}
	argv, _, _ := strings.Cut(stdout, " LEN:")
	if strings.Contains(argv, credExecSecret) {
		t.Fatalf("the credential appeared in argv: %q", argv)
	}
}

// TestRunCredentialExec_CapsEachStream — safeguard 5. Both streams are capped
// independently and either one overflowing raises the flag.
func TestRunCredentialExec_CapsEachStream(t *testing.T) {
	sh := credExecFixtureShell(t)
	args := []string{"-c", `printf "0123456789ABCDEF"; printf "abcdefghijklmnop" >&2`}

	result, err := runCredentialExec(sh, args, t.TempDir(), cleanExecEnv(nil), 10*time.Second, 10)
	if err != nil {
		t.Fatalf("runCredentialExec: %v", err)
	}
	if string(result.Stdout) != "0123456789" {
		t.Fatalf("stdout = %q, want the first 10 bytes", result.Stdout)
	}
	if string(result.Stderr) != "abcdefghij" {
		t.Fatalf("stderr = %q, want the first 10 bytes", result.Stderr)
	}
	if !result.Truncated {
		t.Fatal("truncated flag not raised")
	}

	// Exactly at the cap is not truncation.
	exact, err := runCredentialExec(sh, []string{"-c", `printf "0123456789"`}, t.TempDir(),
		cleanExecEnv(nil), 10*time.Second, 10)
	if err != nil {
		t.Fatalf("runCredentialExec: %v", err)
	}
	if exact.Truncated {
		t.Fatal("output exactly at the cap was reported as truncated")
	}
}

// TestRunCredentialExec_TimeoutKillsTheGrandchild — safeguard 4. The child
// leaves a sleeping grandchild and blocks; the timeout signals the whole process
// group, so both are gone when the call returns.
//
// Killing only cmd.Process would leave the grandchild running with the injected
// credential still in its environment, which is the failure this test exists to
// catch.
func TestRunCredentialExec_TimeoutKillsTheGrandchild(t *testing.T) {
	sh := credExecFixtureShell(t)
	// The grandchild reports its own pid, then the child waits on it — so the
	// call cannot return before the timeout.
	args := []string{"-c", `sleep 30 & printf "%s\n" "$!"; wait`}

	start := time.Now()
	result, err := runCredentialExec(sh, args, t.TempDir(), cleanExecEnv(nil), 300*time.Millisecond, defaultCredentialExecMaxStream)
	if err != nil {
		t.Fatalf("runCredentialExec: %v", err)
	}
	if !result.TimedOut {
		t.Fatalf("timed_out = false after %s", time.Since(start))
	}
	if result.ExitCode != -1 {
		t.Fatalf("exit_code = %d, want -1 on timeout", result.ExitCode)
	}

	pid, convErr := strconv.Atoi(strings.TrimSpace(string(result.Stdout)))
	if convErr != nil || pid <= 0 {
		t.Fatalf("could not read the grandchild pid from %q: %v", result.Stdout, convErr)
	}

	// The kill is asynchronous and the reparented grandchild takes a moment to
	// be reaped, so poll rather than assert instantly.
	deadline := time.Now().Add(5 * time.Second)
	for {
		if err := syscall.Kill(pid, 0); err != nil {
			return // gone
		}
		if time.Now().After(deadline) {
			t.Fatalf("grandchild pid %d survived the process-group kill", pid)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
