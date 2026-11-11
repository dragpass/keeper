//go:build !keeper_e2e

package handlers

import (
	"testing"
	"time"

	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
)

// A release Keeper with no root key built in cannot tell a server key set the
// API published from one any local caller made up, so it installs nothing:
// no versioned slot, no move of the active version, no fingerprint pin. The
// keys it already pins keep verifying server decisions (lv78 review F1).
func TestReleaseRefreshServerKeysWithoutARootKeyInstallsNothing(t *testing.T) {
	deps, _, store := newTestDeps(t)
	resetServerKeySlots(t, store)
	const pinned = "-----BEGIN PUBLIC KEY-----\nPINNED\n-----END PUBLIC KEY-----\n"
	if err := keychain.SaveServerPublicKeyForVersion(store, 1, pinned); err != nil {
		t.Fatal(err)
	}
	if err := keychain.SaveActiveServerKeyVersion(store, 1); err != nil {
		t.Fatal(err)
	}

	resp := HandleRefreshServerKeys(deps, RefreshServerKeysRequest{
		Keys: []SystemServerKeyEntry{{
			Version:      7,
			PublicKeyPEM: "-----BEGIN PUBLIC KEY-----\nUNSIGNED\n-----END PUBLIC KEY-----\n",
			IssuedAt:     time.Unix(1700000000, 0),
			ExpiresAt:    time.Unix(1800000000, 0),
			Status:       "active",
		}},
		RootPublicKeyFingerprint: "sha256:unverified",
	})
	if resp.Success || resp.ErrorCode != string(errs.ErrCodeCryptoFailure) {
		t.Fatalf("unverified server keys in a release build: %+v", resp)
	}
	if _, err := keychain.GetServerPublicKeyByVersion(store, 7); err == nil {
		t.Fatal("an unverified key was stored as version 7")
	}
	if active, err := keychain.GetActiveServerKeyVersion(store); err != nil || active != 1 {
		t.Fatalf("active version = %d, %v; want 1", active, err)
	}
	if pin, _ := keychain.GetRootPublicKeyFingerprint(store); pin != "" {
		t.Fatalf("fingerprint pinned without a root key: %q", pin)
	}
}
