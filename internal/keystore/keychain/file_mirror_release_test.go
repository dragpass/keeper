//go:build !keeper_e2e

package keychain

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/zalando/go-keyring"
)

// Without the keeper_e2e tag KEEPER_E2E_KEYRING_FILE is not read: keyring
// writes are not copied to the file and the file cannot inject entries.
func TestReleaseKeyringIgnoresTheE2EMirrorFile(t *testing.T) {
	keyring.MockInit()
	path := filepath.Join(t.TempDir(), "keyring.json")
	t.Setenv("KEEPER_E2E_KEYRING_FILE", path)

	if err := krSet("svc", "written", "secret"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("keyring write reached the mirror file: %v", err)
	}

	if err := os.WriteFile(path, []byte(`{"svc|injected":"value"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := krGet("svc", "injected"); !errors.Is(err, keyring.ErrNotFound) {
		t.Fatalf("mirror file injected a keyring entry: %v", err)
	}
}
