// rotate_keypair_prepare_test.go — HandleRotateUserKeypairPrepare 가드.
//
// **Defects this test catches:**
//   - regressions where Prepare calls free `VerifyServerSig` directly
//     (bypassing a.ServerKeyVerifier.Verify)
//   - regressions where the handler calls stdlib `log.*` directly (bypassing a.Logger)
package handlers

import (
	"errors"
	"strings"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

func TestApp_HandleRotateUserKeypairPrepare_VerifyFailedShortCircuits(t *testing.T) {
	deps, log, _ := newTestDepsFailVerify(t, errors.New("server signature verification failed: stub"))

	resp := HandleRotateUserKeypairPrepare(deps, proto.RotateUserKeypairPrepareRequest{
		ChallengeToken:  "any-challenge",
		ServerSignature: "any-sig",
	})

	if resp.Success {
		t.Fatalf("expected failure when ServerKeyVerifier rejects")
	}
	if !strings.Contains(resp.Error, "server signature verification failed") {
		t.Fatalf("error must include verifier failure prefix, got %q", resp.Error)
	}

	// The single "processing..." line must be logged, but the success log must not appear.
	if !log.Contains("rotate user keypair prepare request processing") {
		t.Fatalf("expected 'processing...' log")
	}
	if log.Contains("prepare successful") {
		t.Fatalf("must not log success on verify failure: %v", log.Messages())
	}
}

func TestHandleRotateUserKeypairPrepare_ValidationDelegation(t *testing.T) {
	deps, _, _ := newTestDeps(t)
	resp := HandleRotateUserKeypairPrepare(deps, proto.RotateUserKeypairPrepareRequest{
		ChallengeToken:  "", // empty → validation fail
		ServerSignature: "",
	})
	if resp.Success {
		t.Fatalf("expected validation failure")
	}
	if resp.Error == "" {
		t.Fatalf("expected non-empty error")
	}
}

// ────────────────────────────────────────────────────────────────────────
// Production-ish tests migrated from the keystore root's
// rotate_keypair_facade_test.go. Helpers were updated to use deps's
// SecretStore directly.
//
// Coverage:
//   1. prepare: generate new keypair → save into pending slot + emit both signatures
//   2. prepare: forged server signature → reject
//   3. prepare must not touch ACTIVE (OLD priv preserved)
//   4. promote: normal flow → pending → active promotion, OLD discarded
//   5. promote: forged server signature → reject, pending preserved
//   6. promote: no pending → reject
//   7. round-trip: prepare → promote, then active = NEW
//   8~11. status / abort actions
// ────────────────────────────────────────────────────────────────────────

// seedActiveKeypairForRotateTest seeds the user's active keypair.
// In this package it writes directly to deps.Store (= MemorySecretStore).
func seedActiveKeypairForRotateTest(t *testing.T, store keychain.SecretStore) (oldPubPEM string, oldPriv *crypto.KeyPair) {
	t.Helper()
	_ = keychain.DeletePrivateKey(store)
	_ = keychain.DeletePublicKey(store)
	_ = keychain.DeletePendingPrivateKey(store)
	_ = keychain.DeletePendingPublicKey(store)

	kp, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("active keypair: %v", err)
	}
	if err := keychain.SavePrivateKey(store, kp.PrivateKey); err != nil {
		t.Fatalf("SavePrivateKey: %v", err)
	}
	if err := keychain.SavePublicKey(store, kp.PublicKey); err != nil {
		t.Fatalf("SavePublicKey: %v", err)
	}
	return kp.PublicKey, kp
}

func TestHandleRotateUserKeypairPrepare_Success(t *testing.T) {
	deps, _, store := newTestDeps(t)
	oldPub, _ := seedActiveKeypairForRotateTest(t, store)

	resp := HandleRotateUserKeypairPrepare(deps, proto.RotateUserKeypairPrepareRequest{
		ChallengeToken:  "rotate-challenge-001",
		ServerSignature: "any",
	})
	if !resp.Success {
		t.Fatalf("prepare failed: %s", resp.Error)
	}
	data := resp.Data.(proto.RotateUserKeypairPrepareResponseData)
	if data.NewPublicKey == "" {
		t.Errorf("missing NewPublicKey")
	}
	if data.OldSignature == "" || data.NewSignature == "" {
		t.Errorf("missing signatures")
	}
	if data.NewPublicKey == oldPub {
		t.Errorf("NewPublicKey unexpectedly equals OldPublicKey")
	}

	// verify it was saved into the pending slot
	pendingPriv, err := keychain.GetPendingPrivateKey(store)
	if err != nil || pendingPriv == "" {
		t.Errorf("pending priv not stored: %v", err)
	}
	pendingPub, err := keychain.GetPendingPublicKey(store)
	if err != nil || pendingPub == "" {
		t.Errorf("pending pub not stored: %v", err)
	}

	// ACTIVE must be preserved
	activePub, err := keychain.GetPublicKey(store)
	if err != nil || activePub != oldPub {
		t.Errorf("active pub changed during prepare: got %q want %q", activePub, oldPub)
	}
}

func TestHandleRotateUserKeypairPrepare_RejectsBadServerSig(t *testing.T) {
	// AlwaysFailVerifier — server-sig verification fails
	deps, _, store := newTestDepsFailVerify(t, errors.New("server signature verification failed: stub"))
	seedActiveKeypairForRotateTest(t, store)

	resp := HandleRotateUserKeypairPrepare(deps, proto.RotateUserKeypairPrepareRequest{
		ChallengeToken:  "rotate-challenge-002",
		ServerSignature: "any",
	})
	if resp.Success {
		t.Fatalf("expected prepare to reject bad server signature")
	}
	if _, err := keychain.GetPendingPrivateKey(store); err == nil {
		t.Errorf("pending priv should not be stored on rejected prepare")
	}
}
