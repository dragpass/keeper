//go:build windows

// credential_exec_proc_windows.go — the exec sink is unavailable on Windows.
//
// Windows has no counterpart to Setpgid + kill(-pgid). Killing a tree needs a
// Job Object created and assigned before the child starts, which is a different
// mechanism with its own failure modes. Until that exists, a timeout here would
// kill the direct child and leave any grandchild running with the injected
// credential still in its environment.
//
// A safeguard that does not work must not be presented as one, so the handler
// refuses the action outright on this platform rather than running it with a
// timeout that half-applies. The stubs below exist only to keep the package
// compiling.

package handlers

import "os/exec"

// credentialExecSupported gates the whole action. false here makes
// HandleCredentialExecRequest fail with ErrCodeUnsupported before it touches
// the sealed payload.
const credentialExecSupported = false

func applyProcessGroup(_ *exec.Cmd) {}

func killProcessGroup(cmd *exec.Cmd) {
	if cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
}
