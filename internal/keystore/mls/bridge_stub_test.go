//go:build !mls || !cgo

package mls

import (
	"errors"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/keychain"
)

// The default build has to say "no library" rather than "no group", because a
// caller that cannot tell those apart will retry the wrong one forever.
func TestDefaultBuildAnswersUnavailable(t *testing.T) {
	if Available() {
		t.Fatal("Available() is true in a build without the mls tag")
	}
	if _, err := Version(); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Version() = %v; want ErrUnavailable", err)
	}
	if _, err := openSession(nil, nil, nil); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("openSession() = %v; want ErrUnavailable", err)
	}
	if _, err := NewDeviceSession(keychain.NewMemorySecretStore()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("NewDeviceSession() = %v; want ErrUnavailable", err)
	}
}
