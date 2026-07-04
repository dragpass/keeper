// verifier.go unit tests (verifier-package residency).
//
// Previous location: internal/keystore/server_key_verifier_test.go.
//
// **Defects this test catches:**
//   - DefaultServerKeyVerifier diverging from VerifyServerSig delegation
//     (whether key-not-found / parse-failure prefixes are preserved)
//   - AlwaysOKVerifier failing to return nil regardless of input
//   - AlwaysFailVerifier's default error message diverging from external
//     patterns
//   - NewDefaultServerKeyVerifier failing to encapsulate the SecretStore field

package verifier

import (
	"errors"
	"strings"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/keychain"
)

func TestAlwaysOKVerifier_AcceptsAnyInput(t *testing.T) {
	v := AlwaysOKVerifier{}
	cases := []struct {
		token, sig string
		ver        uint
	}{
		{"any", "any", 0},
		{"", "", 1},
		{"long-challenge-token", "AAAAAAAA", 99},
	}
	for _, c := range cases {
		if err := v.Verify(c.token, c.sig, c.ver); err != nil {
			t.Errorf("AlwaysOK rejected (%v): %v", c, err)
		}
	}
}

func TestAlwaysFailVerifier_DefaultErrorMessage(t *testing.T) {
	v := AlwaysFailVerifier{}
	err := v.Verify("any", "any", 0)
	if err == nil {
		t.Fatalf("expected error")
	}
	// Preserve the prefix that existing handler code checks.
	if !strings.Contains(err.Error(), "server signature verification failed") {
		t.Fatalf("error must include 'server signature verification failed' prefix, got %q", err.Error())
	}
}

func TestAlwaysFailVerifier_RespectsCustomError(t *testing.T) {
	custom := errors.New("custom verifier failure")
	v := AlwaysFailVerifier{Err: custom}
	err := v.Verify("any", "any", 0)
	if !errors.Is(err, custom) {
		t.Fatalf("expected custom error, got %v", err)
	}
}

func TestDefaultServerKeyVerifier_DelegatesToVerifyServerSig(t *testing.T) {
	// Empty MemorySecretStore — no server key registered.
	store := keychain.NewMemorySecretStore()
	v := NewDefaultServerKeyVerifier(store)

	err := v.Verify("any-challenge", "AAAA", 1)
	if err == nil {
		t.Fatalf("expected error when no server key seeded")
	}
	if !strings.Contains(err.Error(), "failed to get server public key") {
		t.Fatalf("expected key lookup failure prefix, got %q", err.Error())
	}
}

func TestNewDefaultServerKeyVerifier_HoldsStore(t *testing.T) {
	store := keychain.NewMemorySecretStore()
	v := NewDefaultServerKeyVerifier(store)
	if v.Store == nil {
		t.Fatalf("NewDefaultServerKeyVerifier must capture store, got nil")
	}
	// Confirm it's the same store instance (interface comparison is enough).
	if v.Store != store {
		t.Fatalf("Store must be the injected instance")
	}
}
