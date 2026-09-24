//go:build mls && cgo && !windows

package killharness

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
)

// forceKill is SIGKILL: the process dies with its locks held and nothing
// deferred run.
func forceKill(p *os.Process) error { return p.Signal(syscall.SIGKILL) }

// diedOfForceKill reports whether a Wait error is death by SIGKILL.
func diedOfForceKill(err error) bool {
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		return false
	}
	status, ok := exit.Sys().(syscall.WaitStatus)
	return ok && status.Signaled() && status.Signal() == syscall.SIGKILL
}

const binarySuffix = ""

func platformEnv(string) []string { return nil }
