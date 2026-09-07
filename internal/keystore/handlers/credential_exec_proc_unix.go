//go:build !windows

// credential_exec_proc_unix.go — process-group primitives for the exec sink.
//
// The child is put in a new process group of its own and, on timeout, the whole
// group is signalled. Killing only cmd.Process would leave any grandchild the
// child started still running, still holding the injected credential in its
// environment — a timeout that does not do that is not a safeguard.
//
// A grandchild that calls setsid() escapes the group and survives. That gap is
// accepted and recorded in the threat model; it is not something the parent can
// prevent.

package handlers

import (
	"os/exec"
	"syscall"
)

// credentialExecSupported gates the whole action. Unix has the group kill, so
// the sink is available here.
const credentialExecSupported = true

func applyProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// killProcessGroup SIGKILLs the child's whole process group. It falls back to
// killing the child alone only when the group id cannot be read, which means the
// child is already gone.
func killProcessGroup(cmd *exec.Cmd) {
	if cmd.Process == nil {
		return
	}
	if pgid, err := syscall.Getpgid(cmd.Process.Pid); err == nil && pgid > 0 {
		_ = syscall.Kill(-pgid, syscall.SIGKILL)
		return
	}
	_ = cmd.Process.Kill()
}
