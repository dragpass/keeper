// **Defects this test catches:**
//   - DefaultServerKeyVerifier diverging from VerifyServerSig delegation
//     (whether key-not-found / parse-failure prefixes are preserved)
//   - NewDefaultServerKeyVerifier failing to encapsulate the SecretStore field

package verifier

import (
	"strings"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/testdouble"
)

func TestDefaultServerKeyVerifier_DelegatesToVerifyServerSig(t *testing.T) {
	// Empty MemorySecretStore — no server key registered.
	store := testdouble.NewMemorySecretStore()
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
	store := testdouble.NewMemorySecretStore()
	v := NewDefaultServerKeyVerifier(store)
	if v.Store == nil {
		t.Fatalf("NewDefaultServerKeyVerifier must capture store, got nil")
	}
	// Confirm it's the same store instance (interface comparison is enough).
	if v.Store != store {
		t.Fatalf("Store must be the injected instance")
	}
}
