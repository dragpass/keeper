//go:build !darwin && !linux

// Package proc — process-level hardening hooks. Noop on Windows / other OSes.
package proc

// DisableCoreDumps is a noop on Windows and similar OSes. WER (Windows Error
// Reporting) policy is a separate OS-level setting and is not handled by this
// function.
func DisableCoreDumps() error { return nil }
