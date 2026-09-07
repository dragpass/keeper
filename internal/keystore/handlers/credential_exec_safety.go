// credential_exec_safety.go — the security-critical helpers behind
// credential_exec_request, isolated from the handler orchestration in
// credential_exec.go so a security reviewer can read (and the tests can
// exercise) each safeguard on its own.
//
// Resident helpers:
//   - substituteSecretEnv — {{secret.<key>}} resolution into environment values
//   - cleanExecEnv        — the fixed inheritance allowlist plus the injected variable
//   - runCredentialExec   — the spawn itself: no shell, no PATH lookup, its own
//     process group, per-stream cap, group kill on timeout
//   - readCappedStream    — 1 MiB LimitReader read with a truncation flag
//
// The process-group primitives live in credential_exec_proc_unix.go /
// _windows.go, because a timeout that kills only the direct child is not a
// timeout — it leaves a grandchild holding the credential.

package handlers

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"sync"
	"time"
)

const (
	// These limits are Keeper-owned and are not caller-configurable, for the
	// same reason the HTTP sink's are: the server policy signature does not
	// cover resource-limit fields, so anything the request could set would be
	// unsigned. The handler passes the constants; the parameters exist so the
	// tests can drive the same code on a human timescale.
	defaultCredentialExecTimeout   = 60 * time.Second
	defaultCredentialExecMaxStream = 1 << 20 // 1 MiB per stream
)

// credentialExecEnvAllowlist is the entire set of the Keeper's own environment
// variables a credentialed child inherits. Everything else is dropped.
//
// Inheriting the caller's environment wholesale is what this sink exists to
// avoid: the MCP process holds DRAGPASS_API_TOKEN, and a child that receives it
// can resolve every other credential the token can reach. The list is fixed
// rather than policy-configurable — when a real tool turns out to need
// SSH_AUTH_SOCK or GH_CONFIG_DIR, that is a policy field to add deliberately,
// not a hole to leave open in advance.
var credentialExecEnvAllowlist = []string{
	"PATH", "HOME", "USER", "LOGNAME", "SHELL", "LANG", "LC_ALL", "TMPDIR", "TZ", "TERM",
}

// substituteSecretEnv resolves the environment template against the decrypted
// secret and returns the assembled variables plus the distinct secret strings
// actually injected (which later drive output redaction).
//
// It is substituteSecretHeaders' sibling and shares resolveSecretPlaceholders,
// so a placeholder naming a key the payload does not carry is an error in both
// sinks: the process must not start with an empty credential in its
// environment.
func substituteSecretEnv(template map[string]string, secret map[string]string) (map[string]string, []string, error) {
	assembled := make(map[string]string, len(template))
	injectedSet := map[string]bool{}
	for name, tmpl := range template {
		resolved, err := resolveSecretPlaceholders("env_template", tmpl, secret, injectedSet)
		if err != nil {
			return nil, nil, err
		}
		assembled[name] = resolved
	}
	return assembled, sortedInjected(injectedSet), nil
}

// cleanExecEnv builds the child's environment: the allowlisted variables the
// Keeper itself has, plus the injected ones. An injected name that collides with
// an allowlisted one replaces it rather than being appended after it, so the
// child never sees the same name twice with different values.
//
// Output is deterministic (allowlist order, then injected names sorted) so tests
// and any future logging of *names* stay stable.
func cleanExecEnv(injected map[string]string) []string {
	env := make([]string, 0, len(credentialExecEnvAllowlist)+len(injected))
	for _, name := range credentialExecEnvAllowlist {
		if _, overridden := injected[name]; overridden {
			continue
		}
		if value, ok := os.LookupEnv(name); ok {
			env = append(env, name+"="+value)
		}
	}
	names := make([]string, 0, len(injected))
	for name := range injected {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		env = append(env, name+"="+injected[name])
	}
	return env
}

// execResult is runCredentialExec's raw (un-redacted) outcome.
type execResult struct {
	ExitCode  int
	Stdout    []byte
	Stderr    []byte
	Truncated bool
	TimedOut  bool
}

// runCredentialExec spawns exactly one child process and collects its output.
//
// Safeguards implemented here:
//   - No shell, ever. The Cmd is built by hand with Path set to the absolute
//     executable, so os/exec performs no PATH lookup and there is no code path
//     that reaches "sh -c".
//   - No inherited stdin. A credentialed child gets nothing to read.
//   - Its own process group (applyProcessGroup), killed as a group on timeout
//     (killProcessGroup) so a grandchild the child left sleeping dies too.
//   - Each stream is read through a LimitReader and flagged when it overflows.
//   - A non-zero exit is data, not an error: it comes back as ExitCode. Only a
//     timeout is special, reporting ExitCode -1 because the process never chose
//     one.
//
// env must already be the cleaned environment (cleanExecEnv). The secret is in
// env and never in argv.
func runCredentialExec(
	executable string, args []string, cwd string, env []string,
	timeout time.Duration, maxStream int64,
) (execResult, error) {
	cmd := &exec.Cmd{
		Path:  executable,
		Args:  append([]string{executable}, args...),
		Dir:   cwd,
		Env:   env,
		Stdin: nil,
	}
	applyProcessGroup(cmd)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return execResult{}, fmt.Errorf("cannot open stdout pipe")
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return execResult{}, fmt.Errorf("cannot open stderr pipe")
	}
	if err := cmd.Start(); err != nil {
		// The error text can name the executable (a signed, human-approved value)
		// but never the environment, so it carries no secret.
		return execResult{}, fmt.Errorf("cannot start process: %w", err)
	}

	var (
		wg                     sync.WaitGroup
		outBuf, errBuf         []byte
		outTruncated, errTrunc bool
	)
	wg.Add(2)
	go func() { defer wg.Done(); outBuf, outTruncated = readCappedStream(stdout, maxStream) }()
	go func() { defer wg.Done(); errBuf, errTrunc = readCappedStream(stderr, maxStream) }()

	// Both pipes must be drained before Wait (os/exec contract). Draining also
	// means a grandchild holding the pipe open keeps us here until the timeout
	// kills the group — which is the behaviour we want, not a hang: the caller
	// gets a timed_out response and the grandchild is dead.
	done := make(chan error, 1)
	go func() {
		wg.Wait()
		done <- cmd.Wait()
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case waitErr := <-done:
		return execResult{
			ExitCode:  exitCodeOf(waitErr),
			Stdout:    outBuf,
			Stderr:    errBuf,
			Truncated: outTruncated || errTrunc,
		}, nil
	case <-timer.C:
		killProcessGroup(cmd)
		// Reap. The kill closes the pipes, so the readers finish and Wait
		// returns; whatever the streams produced before the kill is still
		// returned, redacted like any other output.
		<-done
		return execResult{
			ExitCode:  -1,
			Stdout:    outBuf,
			Stderr:    errBuf,
			Truncated: outTruncated || errTrunc,
			TimedOut:  true,
		}, nil
	}
}

// readCappedStream reads at most maxBytes from r (+1 byte to detect the
// overflow) and reports whether it truncated. A read error is treated as
// end-of-stream: whatever arrived is what the caller sees, and the exit code
// carries the process's own verdict.
func readCappedStream(r io.Reader, maxBytes int64) ([]byte, bool) {
	raw, err := io.ReadAll(io.LimitReader(r, maxBytes+1))
	if err != nil {
		if int64(len(raw)) > maxBytes {
			return raw[:maxBytes], true
		}
		return raw, false
	}
	if int64(len(raw)) > maxBytes {
		return raw[:maxBytes], true
	}
	return raw, false
}

// exitCodeOf turns cmd.Wait's error into the process's exit code. A clean exit
// is 0; a non-zero exit is that code; anything else (signal, wait failure) is
// -1, the same value a timeout reports.
func exitCodeOf(waitErr error) int {
	if waitErr == nil {
		return 0
	}
	var exitErr *exec.ExitError
	if errors.As(waitErr, &exitErr) {
		if code := exitErr.ExitCode(); code >= 0 {
			return code
		}
	}
	return -1
}
