// Tests server public-key bootstrap and idempotency.
package keychain

import (
	"strings"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/crypto"
)

func TestEnsureServerPublicKey_FirstRun(t *testing.T) {
	store := defaultKeyringStore()
	resetServerKeySlots(t, store)

	err := EnsureServerPublicKey(store, discardLogger{})
	if err != nil {
		t.Fatalf("EnsureServerPublicKey() error = %v", err)
	}

	key, err := GetActiveServerPublicKey(store)
	if err != nil {
		t.Fatalf("GetActiveServerPublicKey() error = %v", err)
	}

	if !strings.Contains(key, "PUBLIC KEY") {
		t.Error("server public key should be in PEM format")
	}
}

func TestEnsureServerPublicKey_Idempotent(t *testing.T) {
	store := defaultKeyringStore()
	resetServerKeySlots(t, store)

	log := discardLogger{}
	// First call
	_ = EnsureServerPublicKey(store, log)
	key1, _ := GetActiveServerPublicKey(store)

	// Second call should not overwrite
	_ = EnsureServerPublicKey(store, log)
	key2, _ := GetActiveServerPublicKey(store)

	if key1 != key2 {
		t.Error("EnsureServerPublicKey should be idempotent")
	}
}

func TestEnsureServerPublicKey_ValidRSAKey(t *testing.T) {
	store := defaultKeyringStore()
	resetServerKeySlots(t, store)
	_ = EnsureServerPublicKey(store, discardLogger{})

	key, _ := GetActiveServerPublicKey(store)

	// Should be parseable as an RSA public key
	pub, err := crypto.ParsePublicKey(key)
	if err != nil {
		t.Fatalf("server public key is not a valid RSA key: %v", err)
	}

	if pub.N.BitLen() < 2048 {
		t.Errorf("server public key size = %d bits, want >= 2048", pub.N.BitLen())
	}
}
