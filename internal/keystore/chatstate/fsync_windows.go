//go:build windows

package chatstate

// syncDir has no Windows counterpart that this repo has established. The ADR
// lists both this and the durability of a rename over an existing file as
// things to measure before the Windows path is claimed to be atomic, so nothing
// is claimed here.
func syncDir(string) error { return nil }
