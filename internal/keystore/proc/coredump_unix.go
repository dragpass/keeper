//go:build darwin || linux

// Package proc — process-level hardening hooks (coredump policy etc.).
package proc

import "syscall"

// DisableCoreDumps sets RLIMIT_CORE to 0 so that a process crash does not
// write a core dump to disk. Closes the surface where plaintext could be
// exposed in a core file.
//
// Failure is not fatal — the caller (main.go) only logs a warning and continues.
func DisableCoreDumps() error {
	return syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{Cur: 0, Max: 0})
}
