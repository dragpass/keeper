package handlers

import (
	"bytes"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// Until the server accepts the signup (save_session_code), the new DEK is
// pending: a prepare that is never completed leaves the active DEK alone, a
// retried prepare replaces only the pending one, and completion promotes it.
func TestAuthSignupPrepareKeepsTheNewDEKPendingUntilTheSessionCodeIsSaved(t *testing.T) {
	deps, _, store := newTestDeps(t)
	setKeychainDeviceKey(t, store, bytes.Repeat([]byte{0x44}, 32))
	if err := keychain.SavePersonalDeviceWrappedDEK(store, "dek-from-an-earlier-identity"); err != nil {
		t.Fatal(err)
	}
	first := HandleAuthSignupPrepare(deps, signupRequest())
	second := HandleAuthSignupPrepare(deps, signupRequest())
	if !first.Success || !second.Success {
		t.Fatalf("prepare failed: %+v / %+v", first, second)
	}
	active, err := keychain.GetPersonalDeviceWrappedDEK(store)
	if err != nil || active != "dek-from-an-earlier-identity" {
		t.Fatalf("active DEK before completion = %q, %v", active, err)
	}
	pending, err := keychain.GetPendingSignupDeviceWrappedDEK(store)
	want := second.Data.(proto.AuthSignupPrepareResponseData).DeviceWrappedDEKB64
	if err != nil || pending != want {
		t.Fatalf("pending DEK = %q, %v; want the retried prepare's", pending, err)
	}

	promoted, err := keychain.PromotePendingKeypair(store)
	if err != nil || !promoted {
		t.Fatalf("promote keypair: %v %v", promoted, err)
	}
	if err := keychain.PromotePendingSignupDEK(store, promoted); err != nil {
		t.Fatal(err)
	}
	if active, _ := keychain.GetPersonalDeviceWrappedDEK(store); active != want {
		t.Fatalf("active DEK after completion = %q, want %q", active, want)
	}
	if _, err := keychain.GetPendingSignupDeviceWrappedDEK(store); err == nil {
		t.Fatal("pending DEK survived its promotion")
	}
	// A repeated completion (a retried save_session_code) is a no-op.
	if err := keychain.PromotePendingSignupDEK(store, false); err != nil {
		t.Fatal(err)
	}
	if active, _ := keychain.GetPersonalDeviceWrappedDEK(store); active != want {
		t.Fatal("a repeated completion changed the active DEK")
	}
}

// A pending DEK left by an abandoned signup is never promoted by an unrelated
// session-code save (login on another device, no pending keypair).
func TestStalePendingSignupDEKIsDroppedNotPromoted(t *testing.T) {
	_, _, store := newTestDeps(t)
	if err := keychain.SavePersonalDeviceWrappedDEK(store, "active"); err != nil {
		t.Fatal(err)
	}
	if err := keychain.SavePendingSignupDeviceWrappedDEK(store, "stale"); err != nil {
		t.Fatal(err)
	}
	if err := keychain.PromotePendingSignupDEK(store, false); err != nil {
		t.Fatal(err)
	}
	if active, _ := keychain.GetPersonalDeviceWrappedDEK(store); active != "active" {
		t.Fatalf("active DEK = %q", active)
	}
	if _, err := keychain.GetPendingSignupDeviceWrappedDEK(store); err == nil {
		t.Fatal("stale pending DEK was kept")
	}
}
