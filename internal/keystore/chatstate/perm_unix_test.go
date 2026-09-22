//go:build !windows

package chatstate

import (
	"os"
	"testing"
)

func assertOwnerOnlyAccess(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("record permissions = %o, want 600", perm)
	}
}
