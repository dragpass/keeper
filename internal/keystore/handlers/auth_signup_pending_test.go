package handlers

import (
	"bytes"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// Until the server accepts the signup (save_session_code), the new DEK is
// pending: a prepare that is never completed leaves the active DEK alone, a
// retried prepare with the same input answers for the staged DEK instead of
// replacing it, and completion promotes it.
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
	want := first.Data.(proto.AuthSignupPrepareResponseData).DeviceWrappedDEKB64
	if err != nil || pending != want || second.Data.(proto.AuthSignupPrepareResponseData).DeviceWrappedDEKB64 != want {
		t.Fatalf("pending DEK = %q, %v; want the first prepare's, answered again by the retry", pending, err)
	}

	accepted, _, err := keychain.AcceptSessionCode(store, openAnySessionCode)
	if err != nil || accepted != keychain.SessionCodeAcceptedSignup {
		t.Fatalf("accept session code: %q %v", accepted, err)
	}
	if active, _ := keychain.GetPersonalDeviceWrappedDEK(store); active != want {
		t.Fatalf("active DEK after completion = %q, want %q", active, want)
	}
	if _, err := keychain.GetPendingSignupDeviceWrappedDEK(store); err == nil {
		t.Fatal("pending DEK survived its promotion")
	}
	// A repeated completion (a retried save_session_code) is a no-op.
	if accepted, _, err := keychain.AcceptSessionCode(store, openAnySessionCode); err != nil ||
		accepted != keychain.SessionCodeAcceptedActive {
		t.Fatalf("repeated accept: %q %v", accepted, err)
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
	if err := keychain.SavePrivateKey(store, "active-private-key"); err != nil {
		t.Fatal(err)
	}
	if accepted, _, err := keychain.AcceptSessionCode(store, openAnySessionCode); err != nil ||
		accepted != keychain.SessionCodeAcceptedActive {
		t.Fatalf("accept session code: %q %v", accepted, err)
	}
	if active, _ := keychain.GetPersonalDeviceWrappedDEK(store); active != "active" {
		t.Fatalf("active DEK = %q", active)
	}
	if _, err := keychain.GetPendingSignupDeviceWrappedDEK(store); err == nil {
		t.Fatal("stale pending DEK was kept")
	}
}

// openAnySessionCode stands in for the server's session code, which opens with
// whichever key AcceptSessionCode tries first.
func openAnySessionCode(string) (string, bool) { return "session-code", true }
