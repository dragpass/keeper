// bootstrap_test.go — EnsureServerPublicKey first-boot / idempotency /
// valid RSA key checks.
//
// **Previous location:** internal/keystore/bootstrap_test.go.
package keychain

import (
	"strings"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/logger"
)

func TestEnsureServerPublicKey_FirstRun(t *testing.T) {
	store := defaultKeyringStore()
	// Clear any existing server public key
	_ = DeleteServerPublicKey(store)

	err := EnsureServerPublicKey(store, logger.NewMemoryLogger())
	if err != nil {
		t.Fatalf("EnsureServerPublicKey() error = %v", err)
	}

	key, err := GetServerPublicKey(store)
	if err != nil {
		t.Fatalf("GetServerPublicKey() error = %v", err)
	}

	if !strings.Contains(key, "PUBLIC KEY") {
		t.Error("server public key should be in PEM format")
	}
}

func TestEnsureServerPublicKey_Idempotent(t *testing.T) {
	store := defaultKeyringStore()
	_ = DeleteServerPublicKey(store)

	log := logger.NewMemoryLogger()
	// First call
	_ = EnsureServerPublicKey(store, log)
	key1, _ := GetServerPublicKey(store)

	// Second call should not overwrite
	_ = EnsureServerPublicKey(store, log)
	key2, _ := GetServerPublicKey(store)

	if key1 != key2 {
		t.Error("EnsureServerPublicKey should be idempotent")
	}
}

func TestEnsureServerPublicKey_ValidRSAKey(t *testing.T) {
	store := defaultKeyringStore()
	_ = DeleteServerPublicKey(store)
	_ = EnsureServerPublicKey(store, logger.NewMemoryLogger())

	key, _ := GetServerPublicKey(store)

	// Should be parseable as an RSA public key
	pub, err := crypto.ParsePublicKey(key)
	if err != nil {
		t.Fatalf("server public key is not a valid RSA key: %v", err)
	}

	if pub.N.BitLen() < 2048 {
		t.Errorf("server public key size = %d bits, want >= 2048", pub.N.BitLen())
	}
}
