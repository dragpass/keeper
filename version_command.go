package main

import (
	"fmt"
	"io"

	"github.com/dragpass/keeper/internal/keystore/version"
)

// printVersion answers `dragpass-keeper version` without touching the
// keychain or clipboard, so the release probe can check a shipped binary on a
// bare machine. A release binary has no in-memory keyring to fall back on.
func printVersion(w io.Writer) {
	fmt.Fprintf(w, "version: %s\n", version.Version)
	if report := mlsLibraryReport(); report != "" {
		fmt.Fprintln(w, report)
	}
}
