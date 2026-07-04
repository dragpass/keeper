// server_keys_test.go — multi-version server public key Keychain save / lookup
// / active pointer.
//
// **Previous location:** internal/keystore/server_keys_test.go.
package keychain

import (
	"testing"

	"github.com/dragpass/keeper/config"
	"github.com/dragpass/keeper/internal/keystore/logger"
)

func resetServerKeySlots(t *testing.T, store SecretStore) {
	t.Helper()
	_ = DeleteServerPublicKey(store)
	_ = DeleteServerPublicKeyForVersion(store, 1)
	_ = DeleteServerPublicKeyForVersion(store, 2)
	_ = DeleteServerPublicKeyForVersion(store, 3)
	_ = KrDelete(config.Service, config.DragPassServerPublicKeyActiveVersion)
	_ = KrDelete(config.Service, config.DragPassServerRootPublicKeyFingerprint)
}

func TestSaveAndGetServerPublicKeyByVersion(t *testing.T) {
	store := defaultKeyringStore()
	resetServerKeySlots(t, store)

	pemV1 := "-----BEGIN PUBLIC KEY-----\nFAKE-V1\n-----END PUBLIC KEY-----\n"
	pemV2 := "-----BEGIN PUBLIC KEY-----\nFAKE-V2\n-----END PUBLIC KEY-----\n"

	if err := SaveServerPublicKeyForVersion(store, 1, pemV1); err != nil {
		t.Fatalf("save v1: %v", err)
	}
	if err := SaveServerPublicKeyForVersion(store, 2, pemV2); err != nil {
		t.Fatalf("save v2: %v", err)
	}

	got1, err := GetServerPublicKeyByVersion(store, 1)
	if err != nil || got1 != pemV1 {
		t.Fatalf("get v1 = %q err=%v, want %q", got1, err, pemV1)
	}
	got2, err := GetServerPublicKeyByVersion(store, 2)
	if err != nil || got2 != pemV2 {
		t.Fatalf("get v2 = %q err=%v, want %q", got2, err, pemV2)
	}
}

func TestSaveServerPublicKeyForVersion_Rejects(t *testing.T) {
	store := defaultKeyringStore()
	if err := SaveServerPublicKeyForVersion(store, 0, "x"); err == nil {
		t.Errorf("v=0 should be rejected")
	}
	if err := SaveServerPublicKeyForVersion(store, 1, ""); err == nil {
		t.Errorf("empty PEM should be rejected")
	}
}

func TestGetServerPublicKeyByVersion_NotFound(t *testing.T) {
	store := defaultKeyringStore()
	resetServerKeySlots(t, store)

	if _, err := GetServerPublicKeyByVersion(store, 99); err != ErrServerKeyVersionNotFound {
		t.Errorf("v99 should return ErrServerKeyVersionNotFound, got %v", err)
	}
}

func TestActiveServerKeyVersion_RoundTrip(t *testing.T) {
	store := defaultKeyringStore()
	resetServerKeySlots(t, store)

	// If the active pointer is empty, return ErrNoActiveServerKey.
	if _, err := GetActiveServerKeyVersion(store); err != ErrNoActiveServerKey {
		t.Errorf("empty pointer should return ErrNoActiveServerKey, got %v", err)
	}

	if err := SaveActiveServerKeyVersion(store, 7); err != nil {
		t.Fatalf("save active=7: %v", err)
	}
	v, err := GetActiveServerKeyVersion(store)
	if err != nil || v != 7 {
		t.Errorf("active = %d err=%v, want 7", v, err)
	}
}

func TestGetActiveServerPublicKey(t *testing.T) {
	store := defaultKeyringStore()
	resetServerKeySlots(t, store)

	pem := "-----BEGIN PUBLIC KEY-----\nACTIVE\n-----END PUBLIC KEY-----\n"
	if err := SaveServerPublicKeyForVersion(store, 3, pem); err != nil {
		t.Fatalf("save: %v", err)
	}
	if err := SaveActiveServerKeyVersion(store, 3); err != nil {
		t.Fatalf("save active: %v", err)
	}

	got, err := GetActiveServerPublicKey(store)
	if err != nil || got != pem {
		t.Errorf("active pem = %q err=%v, want %q", got, err, pem)
	}
}

func TestGetServerPublicKeyForVersion_FallbackToActive(t *testing.T) {
	store := defaultKeyringStore()
	resetServerKeySlots(t, store)

	pem := "-----BEGIN PUBLIC KEY-----\nACTIVE\n-----END PUBLIC KEY-----\n"
	if err := SaveServerPublicKeyForVersion(store, 2, pem); err != nil {
		t.Fatalf("save: %v", err)
	}
	if err := SaveActiveServerKeyVersion(store, 2); err != nil {
		t.Fatalf("save active: %v", err)
	}

	// version=0 → active fallback
	got, err := GetServerPublicKeyForVersion(store, 0)
	if err != nil || got != pem {
		t.Errorf("v=0 fallback = %q err=%v, want %q", got, err, pem)
	}

	// version=2 → exact slot
	got, err = GetServerPublicKeyForVersion(store, 2)
	if err != nil || got != pem {
		t.Errorf("v=2 = %q err=%v, want %q", got, err, pem)
	}
}

func TestGetServerPublicKeyForVersion_FallbackToLegacyWhenNoActive(t *testing.T) {
	store := defaultKeyringStore()
	resetServerKeySlots(t, store)

	// No active pointer; PEM only in the legacy slot.
	pem := "-----BEGIN PUBLIC KEY-----\nLEGACY\n-----END PUBLIC KEY-----\n"
	if err := SaveServerPublicKey(store, pem); err != nil {
		t.Fatalf("save legacy: %v", err)
	}

	// version=0 + active empty → legacy fallback
	got, err := GetServerPublicKeyForVersion(store, 0)
	if err != nil || got != pem {
		t.Errorf("legacy fallback = %q err=%v, want %q", got, err, pem)
	}
}

func TestRootPublicKeyFingerprint_RoundTrip(t *testing.T) {
	store := defaultKeyringStore()
	resetServerKeySlots(t, store)

	if got, _ := GetRootPublicKeyFingerprint(store); got != "" {
		t.Errorf("empty pin should return empty, got %q", got)
	}

	fp := "sha256:abcdef0123456789"
	if err := SaveRootPublicKeyFingerprint(store, fp); err != nil {
		t.Fatalf("save fingerprint: %v", err)
	}
	got, err := GetRootPublicKeyFingerprint(store)
	if err != nil || got != fp {
		t.Errorf("get fingerprint = %q err=%v, want %q", got, err, fp)
	}

	// Empty string must be a no-op.
	if err := SaveRootPublicKeyFingerprint(store, ""); err != nil {
		t.Errorf("empty save should be no-op, got %v", err)
	}
	got, _ = GetRootPublicKeyFingerprint(store)
	if got != fp {
		t.Errorf("after empty save fingerprint = %q, want unchanged %q", got, fp)
	}
}

func TestBootstrap_PopulatesAllSlots(t *testing.T) {
	store := defaultKeyringStore()
	resetServerKeySlots(t, store)

	if err := EnsureServerPublicKey(store, logger.NewMemoryLogger()); err != nil {
		t.Fatalf("EnsureServerPublicKey: %v", err)
	}

	v, err := GetActiveServerKeyVersion(store)
	if err != nil || v != 1 {
		t.Errorf("after bootstrap active = %d err=%v, want 1", v, err)
	}

	v1, err := GetServerPublicKeyByVersion(store, 1)
	if err != nil || v1 == "" {
		t.Errorf("v1 slot empty after bootstrap: err=%v", err)
	}

	legacy, err := GetServerPublicKey(store)
	if err != nil || legacy != v1 {
		t.Errorf("legacy mirror %q != v1 %q (err=%v)", legacy, v1, err)
	}
}

func TestBootstrap_DoesNotOverwriteAfterRefresh(t *testing.T) {
	store := defaultKeyringStore()
	resetServerKeySlots(t, store)

	// Simulate Refresh having made v2 active.
	pemV2 := "-----BEGIN PUBLIC KEY-----\nROTATED-V2\n-----END PUBLIC KEY-----\n"
	if err := SaveServerPublicKeyForVersion(store, 2, pemV2); err != nil {
		t.Fatalf("save v2: %v", err)
	}
	if err := SaveActiveServerKeyVersion(store, 2); err != nil {
		t.Fatalf("save active=2: %v", err)
	}
	if err := SaveServerPublicKey(store, pemV2); err != nil {
		t.Fatalf("save legacy mirror: %v", err)
	}

	// Second boot: bootstrap must not roll back to v1.
	if err := EnsureServerPublicKey(store, logger.NewMemoryLogger()); err != nil {
		t.Fatalf("EnsureServerPublicKey: %v", err)
	}
	v, _ := GetActiveServerKeyVersion(store)
	if v != 2 {
		t.Errorf("bootstrap clobbered active version: got %d, want 2", v)
	}
	got, _ := GetActiveServerPublicKey(store)
	if got != pemV2 {
		t.Errorf("bootstrap clobbered v2 PEM")
	}
}
