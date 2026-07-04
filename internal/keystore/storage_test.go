// storage_test.go — regression guard for storage.go helpers (device key
// + identity + pending keypair + server keys + root public key
// fingerprint).
//
// **What this catches:**
//   - storage helper calling free `kr*` directly instead of a.Store.
//   - Signature changes in the free-function wrappers.
//   - MemorySecretStore-injected behavior diverging from
//     KeyringSecretStore.
//   - Two *App instances with their own stores not actually being
//     isolated.
//   - KeyringSecretStore bypassing the file mirror and breaking e2e.
//   - server key helpers calling free `kr*` directly instead of a.Store
//     (merged in from the old server_keys_app_test.go).
//   - Composite methods (getActiveServerPublicKey /
//     getServerPublicKeyForVersion) chain-calling free functions
//     instead of other *App methods.
//   - saveRootPublicKeyFingerprint writing an empty fingerprint to the
//     store.
package keystore

import (
	"errors"
	"testing"
)

// TestApp_SaveGetDeviceKey_RoundTripWithMemoryStore: a device key
// saved into an injected MemorySecretStore
// (NewApp(Deps{Store: ...})) round-trips on get from the same *App.
func TestApp_SaveGetDeviceKey_RoundTripWithMemoryStore(t *testing.T) {
	store := NewMemorySecretStore()
	app := NewApp(Deps{Store: store})

	const sentinel = "ROUND_TRIP_DEVICE_KEY_VALUE"
	if err := app.saveDeviceKey(sentinel); err != nil {
		t.Fatalf("saveDeviceKey: %v", err)
	}
	if store.Size() != 1 {
		t.Fatalf("expected 1 entry in store after save, got %d", store.Size())
	}

	got, err := app.getDeviceKey()
	if err != nil {
		t.Fatalf("getDeviceKey: %v", err)
	}
	if got != sentinel {
		t.Fatalf("round-trip mismatch: want %q, got %q", sentinel, got)
	}
}

// TestApp_DeleteDeviceKey_RemovesFromMemoryStore: get after delete must
// return ErrSecretNotFound.
func TestApp_DeleteDeviceKey_RemovesFromMemoryStore(t *testing.T) {
	store := NewMemorySecretStore()
	app := NewApp(Deps{Store: store})

	if err := app.saveDeviceKey("v"); err != nil {
		t.Fatalf("saveDeviceKey: %v", err)
	}
	if err := app.deleteDeviceKey(); err != nil {
		t.Fatalf("deleteDeviceKey: %v", err)
	}
	if store.Size() != 0 {
		t.Fatalf("expected 0 entries after delete, got %d", store.Size())
	}

	_, err := app.getDeviceKey()
	if !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("expected ErrSecretNotFound after delete, got %v", err)
	}
}

// TestApp_PromotePendingKeypair_MovesEntriesInMemoryStore: the pending
// keypair moves to active and the pending entries are removed.
// Regression guard for the pattern where promotePendingKeypair body
// chain-calls other *App methods.
func TestApp_PromotePendingKeypair_MovesEntriesInMemoryStore(t *testing.T) {
	store := NewMemorySecretStore()
	app := NewApp(Deps{Store: store})

	if err := app.savePendingPrivateKey("priv-pem"); err != nil {
		t.Fatalf("savePendingPrivateKey: %v", err)
	}
	if err := app.savePendingPublicKey("pub-pem"); err != nil {
		t.Fatalf("savePendingPublicKey: %v", err)
	}
	if store.Size() != 2 {
		t.Fatalf("expected 2 pending entries, got %d", store.Size())
	}

	promoted, err := app.promotePendingKeypair()
	if err != nil {
		t.Fatalf("promotePendingKeypair: %v", err)
	}
	if !promoted {
		t.Fatalf("expected promoted=true when pending exists")
	}

	// Copied to active and pending removed → only 2 active entries remain in store.
	if store.Size() != 2 {
		t.Fatalf("expected 2 active entries after promotion, got %d", store.Size())
	}
	if got, err := app.getPrivateKey(); err != nil || got != "priv-pem" {
		t.Fatalf("getPrivateKey after promote: %q err=%v", got, err)
	}
	if got, err := app.getPublicKey(); err != nil || got != "pub-pem" {
		t.Fatalf("getPublicKey after promote: %q err=%v", got, err)
	}
	if _, err := app.getPendingPrivateKey(); !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("pending priv must be gone after promote, got err=%v", err)
	}
}

// TestApp_PromotePendingKeypair_NoPendingReturnsFalse: when no pending
// exists, promote returns (false, nil) — preserves existing behavior
// (login-on-another-device flow).
func TestApp_PromotePendingKeypair_NoPendingReturnsFalse(t *testing.T) {
	store := NewMemorySecretStore()
	app := NewApp(Deps{Store: store})

	promoted, err := app.promotePendingKeypair()
	if err != nil {
		t.Fatalf("promotePendingKeypair: %v", err)
	}
	if promoted {
		t.Fatalf("expected promoted=false on empty store")
	}
}

// TestApp_SaveDeviceKey_TwoAppsAreIsolated: when two *App instances
// each get their own MemorySecretStore, entries must stay isolated.
// Regression guard for parallel-unit-test safety — asserts that two
// apps don't share a single store.
func TestApp_SaveDeviceKey_TwoAppsAreIsolated(t *testing.T) {
	store1 := NewMemorySecretStore()
	store2 := NewMemorySecretStore()
	app1 := NewApp(Deps{Store: store1})
	app2 := NewApp(Deps{Store: store2})

	if err := app1.saveDeviceKey("v1"); err != nil {
		t.Fatalf("app1.saveDeviceKey: %v", err)
	}
	if store2.Size() != 0 {
		t.Fatalf("store2 must remain empty when app1 writes, got Size()=%d", store2.Size())
	}
	if _, err := app2.getDeviceKey(); !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("app2 must see no entry, got err=%v", err)
	}
}

// --- Server keys helper regression guard (merged from server_keys_app_test.go) -------

// TestApp_SaveGetServerPublicKeyForVersion_RoundTrip: multi-version
// save + lookup must be isolated by distinct account keys.
func TestApp_SaveGetServerPublicKeyForVersion_RoundTrip(t *testing.T) {
	store := NewMemorySecretStore()
	app := NewApp(Deps{Store: store})

	const pemV1 = "-----BEGIN PUBLIC KEY-----\nV1-PEM\n-----END PUBLIC KEY-----"
	const pemV2 = "-----BEGIN PUBLIC KEY-----\nV2-PEM\n-----END PUBLIC KEY-----"
	if err := app.saveServerPublicKeyForVersion(1, pemV1); err != nil {
		t.Fatalf("saveServerPublicKeyForVersion v1: %v", err)
	}
	if err := app.saveServerPublicKeyForVersion(2, pemV2); err != nil {
		t.Fatalf("saveServerPublicKeyForVersion v2: %v", err)
	}
	if store.Size() != 2 {
		t.Fatalf("expected 2 entries (v1+v2), got %d", store.Size())
	}

	got1, err := app.getServerPublicKeyByVersion(1)
	if err != nil || got1 != pemV1 {
		t.Fatalf("v1 round-trip mismatch: got=%q err=%v", got1, err)
	}
	got2, err := app.getServerPublicKeyByVersion(2)
	if err != nil || got2 != pemV2 {
		t.Fatalf("v2 round-trip mismatch: got=%q err=%v", got2, err)
	}
}

// TestApp_GetServerPublicKeyByVersion_NotFound: missing version must
// return the sentinel error.
func TestApp_GetServerPublicKeyByVersion_NotFound(t *testing.T) {
	app := NewApp(Deps{Store: NewMemorySecretStore()})

	_, err := app.getServerPublicKeyByVersion(99)
	if !errors.Is(err, ErrServerKeyVersionNotFound) {
		t.Fatalf("expected ErrServerKeyVersionNotFound, got %v", err)
	}
}

// TestApp_GetActiveServerKeyVersion_BootstrapEmpty: pre-bootstrap state
// where the active pointer is empty → ErrNoActiveServerKey.
func TestApp_GetActiveServerKeyVersion_BootstrapEmpty(t *testing.T) {
	app := NewApp(Deps{Store: NewMemorySecretStore()})

	_, err := app.getActiveServerKeyVersion()
	if !errors.Is(err, ErrNoActiveServerKey) {
		t.Fatalf("expected ErrNoActiveServerKey on empty pointer, got %v", err)
	}
}

// TestApp_GetServerPublicKeyForVersion_VersionZeroFallsBackToActive:
// version=0 input must fall back to active (composite method regression
// guard).
func TestApp_GetServerPublicKeyForVersion_VersionZeroFallsBackToActive(t *testing.T) {
	store := NewMemorySecretStore()
	app := NewApp(Deps{Store: store})

	const pemActive = "-----BEGIN PUBLIC KEY-----\nACTIVE-PEM\n-----END PUBLIC KEY-----"
	if err := app.saveServerPublicKeyForVersion(7, pemActive); err != nil {
		t.Fatalf("saveServerPublicKeyForVersion v7: %v", err)
	}
	if err := app.saveActiveServerKeyVersion(7); err != nil {
		t.Fatalf("saveActiveServerKeyVersion: %v", err)
	}

	got, err := app.getServerPublicKeyForVersion(0)
	if err != nil {
		t.Fatalf("expected version=0 to fall back to active v7, got err=%v", err)
	}
	if got != pemActive {
		t.Fatalf("expected active v7 PEM via version=0, got %q", got)
	}
}

// TestApp_SaveRootPublicKeyFingerprint_EmptyIsNoop: an empty
// fingerprint must not be written to the store (preserves the
// TOFU-pin-not-set environment).
func TestApp_SaveRootPublicKeyFingerprint_EmptyIsNoop(t *testing.T) {
	store := NewMemorySecretStore()
	app := NewApp(Deps{Store: store})

	if err := app.saveRootPublicKeyFingerprint(""); err != nil {
		t.Fatalf("save empty fp must succeed (no-op), got %v", err)
	}
	if store.Size() != 0 {
		t.Fatalf("empty fp must not write to store, got Size()=%d", store.Size())
	}

	const fp = "sha256:abc123"
	if err := app.saveRootPublicKeyFingerprint(fp); err != nil {
		t.Fatalf("save real fp: %v", err)
	}
	got, err := app.getRootPublicKeyFingerprint()
	if err != nil || got != fp {
		t.Fatalf("fp round-trip: got=%q err=%v", got, err)
	}
}
