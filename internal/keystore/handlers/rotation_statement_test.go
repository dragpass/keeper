// rotation_statement_test.go — the producer side of the account key trust
// model, checked against the verifier that consumes it.
//
// Two things that unit tests on either half alone would miss:
//
//  1. The statements the Keeper produces are the statements the Keeper
//     accepts. Both sides build the canonical from the same helper, so a
//     field-order or formatting change would move them together and stay
//     green; feeding a real prepare response into the real state machine is
//     what pins them to each other.
//  2. The rotated_at bound holds at all three entry points, and holds before
//     anything is signed or written. A recovery that refused the date after
//     installing the new keypair would leave an account rotated with no
//     statement anyone will accept, which is the failure the statement exists
//     to prevent.

package handlers

import (
	"bytes"
	"encoding/base64"
	"testing"
	"time"

	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/recoverykey"
	"github.com/dragpass/keeper/internal/keystore/secure"
)

const statementAccount = "11111111-1111-4111-8111-111111111111"

// ─── producer → verifier ────────────────────────────────────────────────

// A real rotation's statement must carry a peer who pinned the old key across
// to the new one.
func TestRotationStatement_PrepareOutputRotatesAPin(t *testing.T) {
	deps, _, store := newTestDeps(t)
	oldPubPEM, _ := setupHandlerKeyPair(t, store)
	oldFingerprint := crypto.AccountKeyFingerprint([]byte(oldPubPEM))

	now := time.Now().Unix()
	resp := HandleRotateUserKeypairPrepare(deps, proto.RotateUserKeypairPrepareRequest{
		ChallengeToken:  "rotate-challenge",
		ServerSignature: "any",
		AccountID:       statementAccount,
		Reason:          proto.KeyRotationReasonVoluntary,
		RotatedAt:       now,
	})
	if !resp.Success {
		t.Fatalf("prepare failed: %s", resp.Error)
	}
	data := resp.Data.(proto.RotateUserKeypairPrepareResponseData)
	statement := data.RotationStatement

	// The statement describes the keys the action actually handled.
	if statement.OldFingerprint != oldFingerprint {
		t.Fatalf("old_fingerprint = %q, want the active key's %q", statement.OldFingerprint, oldFingerprint)
	}
	newFingerprint := crypto.AccountKeyFingerprint([]byte(data.NewPublicKey))
	if statement.NewFingerprint != newFingerprint {
		t.Fatalf("new_fingerprint = %q, want the pending key's %q", statement.NewFingerprint, newFingerprint)
	}
	if statement.Reason != proto.KeyRotationReasonVoluntary || statement.AccountID != statementAccount {
		t.Fatalf("statement header = %+v", statement)
	}
	if err := statement.Validate(); err != nil {
		t.Fatalf("produced statement is not structurally valid: %v", err)
	}

	// The verifier the wrap path runs must accept it.
	if err := verifyRotationChain(
		[]proto.KeyRotationStatement{statement}, statementAccount, oldFingerprint, newFingerprint,
	); err != nil {
		t.Fatalf("the Keeper does not accept its own statement: %v", err)
	}

	// And a peer pinned to the old key must advance rather than refuse.
	pinned := &keychain.PeerKeyPin{
		V:           keychain.PeerKeyPinVersion,
		Fingerprint: oldFingerprint,
		State:       keychain.PeerKeyPinStateVerified,
		FirstSeenAt: 1, LastSeenAt: 1, VerifiedAt: 1,
	}
	outcome := evaluatePeerKeyTrust(
		pinned, statementAccount, newFingerprint,
		[]proto.KeyRotationStatement{statement}, now,
	)
	if !outcome.Allowed || outcome.State != keychain.PeerKeyPinStateRotated {
		t.Fatalf("peer got allowed=%t state=%q: %s", outcome.Allowed, outcome.State, outcome.Reason)
	}
	if outcome.Pin.Fingerprint != newFingerprint || outcome.Pin.VerifiedAt != 0 {
		t.Fatalf("pin after rotation = %+v", outcome.Pin)
	}
}

// The recovery flow's statement has to do the same job, with reason fixed and
// the old half taken from the recovery handle rather than the Keychain.
func TestRotationStatement_RecoveryOutputRotatesAPin(t *testing.T) {
	deps, _, _ := newTestDeps(t)

	// The key the recovery restores. It is deliberately NOT the Keychain's
	// active key, so a statement built from the active slot would fail here.
	restored := newTrustKey(t)
	handle := openTestRecoverySession(t, deps, restored.pair.PrivateKey)

	now := time.Now().Unix()
	resp := HandleGenerateKeypairWithRecoveryWrap(deps, proto.GenerateKeypairWithRecoveryWrapRequest{
		ChallengeToken: "recovery-challenge",
		Signature:      "any",
		WrapKeyB64:     base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x07}, 32)),
		AccountID:      statementAccount,
		RotatedAt:      now,
		RecoveryHandle: handle,
	})
	if !resp.Success {
		t.Fatalf("recovery wrap failed: %s", resp.Error)
	}
	data := resp.Data.(proto.GenerateKeypairWithRecoveryWrapResponseData)
	statement := data.RotationStatement

	if statement.Reason != proto.KeyRotationReasonRecovery {
		t.Fatalf("reason = %q, want recovery (the Keeper fixes it, the caller cannot)", statement.Reason)
	}
	if statement.OldFingerprint != restored.fingerprint {
		t.Fatalf("old_fingerprint = %q, want the handle key's %q",
			statement.OldFingerprint, restored.fingerprint)
	}
	newFingerprint := crypto.AccountKeyFingerprint([]byte(data.PublicKey))
	if statement.NewFingerprint != newFingerprint {
		t.Fatalf("new_fingerprint = %q, want the generated key's %q",
			statement.NewFingerprint, newFingerprint)
	}

	outcome := evaluatePeerKeyTrust(
		&keychain.PeerKeyPin{
			V: keychain.PeerKeyPinVersion, Fingerprint: restored.fingerprint,
			State: keychain.PeerKeyPinStateTOFU, FirstSeenAt: 1, LastSeenAt: 1,
		},
		statementAccount, newFingerprint,
		[]proto.KeyRotationStatement{statement}, now,
	)
	if !outcome.Allowed || outcome.State != keychain.PeerKeyPinStateRotated {
		t.Fatalf("a recovery must carry a pin forward, got allowed=%t state=%q: %s",
			outcome.Allowed, outcome.State, outcome.Reason)
	}
}

// ─── the rotated_at bound, all three entry points ───────────────────────

func TestRotatedAtBound_RotatePrepare(t *testing.T) {
	deps, _, store := newTestDeps(t)
	setupHandlerKeyPair(t, store)
	deps.Clock = func() time.Time { return time.Unix(1_000_000, 0) }

	request := func(rotatedAt int64) proto.BaseResponse {
		return HandleRotateUserKeypairPrepare(deps, proto.RotateUserKeypairPrepareRequest{
			ChallengeToken:  "rotate-challenge",
			ServerSignature: "any",
			AccountID:       statementAccount,
			Reason:          proto.KeyRotationReasonVoluntary,
			RotatedAt:       rotatedAt,
		})
	}

	// The edge is inclusive: exactly now+300 is still accepted.
	if resp := request(1_000_000 + proto.KeyRotationPrepareMaxFutureSeconds); !resp.Success {
		t.Fatalf("now+300 refused: %s", resp.Error)
	}
	resp := request(1_000_000 + proto.KeyRotationPrepareMaxFutureSeconds + 1)
	if resp.Success {
		t.Fatal("prepare accepted a rotated_at past the bound")
	}
	if resp.ErrorCode != string(errs.ErrCodeValidation) {
		t.Fatalf("error_code = %q, want validation_error", resp.ErrorCode)
	}
	// Backdating stays allowed: a slow clock must still be able to rotate.
	if resp := request(1); !resp.Success {
		t.Fatalf("backdated rotated_at refused: %s", resp.Error)
	}
}

// The bound has to land before the new keypair reaches the Keychain, or a
// refused date leaves the account rotated with no statement to explain it.
func TestRotatedAtBound_RecoveryWrapLeavesKeychainAlone(t *testing.T) {
	deps, _, store := newTestDeps(t)
	activePubPEM, _ := setupHandlerKeyPair(t, store)
	deps.Clock = func() time.Time { return time.Unix(1_000_000, 0) }

	restored := newTrustKey(t)
	handle := openTestRecoverySession(t, deps, restored.pair.PrivateKey)

	resp := HandleGenerateKeypairWithRecoveryWrap(deps, proto.GenerateKeypairWithRecoveryWrapRequest{
		ChallengeToken: "recovery-challenge",
		Signature:      "any",
		WrapKeyB64:     base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x07}, 32)),
		AccountID:      statementAccount,
		RotatedAt:      1_000_000 + proto.KeyRotationPrepareMaxFutureSeconds + 1,
		RecoveryHandle: handle,
	})
	if resp.Success {
		t.Fatal("recovery wrap accepted a rotated_at past the bound")
	}
	if resp.ErrorCode != string(errs.ErrCodeValidation) {
		t.Fatalf("error_code = %q, want validation_error", resp.ErrorCode)
	}

	stillActive, err := keychain.GetPublicKey(store)
	if err != nil {
		t.Fatalf("GetPublicKey: %v", err)
	}
	if stillActive != activePubPEM {
		t.Fatal("a refused recovery replaced the active keypair")
	}
}

func TestRotatedAtBound_AuthRecoveryPrepare(t *testing.T) {
	deps, _, _ := newTestDeps(t)
	deps.Clock = func() time.Time { return time.Unix(1_000_000, 0) }
	deps.Rand = bytes.NewReader(bytes.Repeat([]byte{0x02}, 256))

	const alias = "alice"
	const enteredRecoveryKey = "ABCD-EFGH-JKLM-NPQR-STUV-WXYZ"

	oldKeypair, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("GenerateRSAKeyPair: %v", err)
	}
	_, oldWrapKey, err := recoverykey.Derive([]byte(enteredRecoveryKey), alias, recoverykey.Version)
	if err != nil {
		t.Fatalf("Derive: %v", err)
	}
	wrappedOldKey, err := crypto.AESGCMEncryptBase64(oldWrapKey, []byte(oldKeypair.PrivateKey))
	secure.Zeroize(oldWrapKey)
	if err != nil {
		t.Fatalf("AESGCMEncryptBase64: %v", err)
	}

	begin := HandleAuthRecoveryBegin(deps, proto.AuthRecoveryBeginRequest{
		Alias: alias, RecoveryKey: enteredRecoveryKey,
	})
	if !begin.Success {
		t.Fatalf("begin failed: %s", begin.Error)
	}
	beginData := begin.Data.(proto.AuthRecoveryBeginResponseData)

	resp := HandleAuthRecoveryPrepare(deps, proto.AuthRecoveryPrepareRequest{
		AccountID:          statementAccount,
		RotatedAt:          1_000_000 + proto.KeyRotationPrepareMaxFutureSeconds + 1,
		Alias:              alias,
		EnteredKeyHandle:   beginData.EnteredKeyHandle,
		ChallengeToken:     "server-challenge",
		Signature:          "server-signature",
		WrappedKeeperB64:   wrappedOldKey,
		RecoveryKeyVersion: recoverykey.Version,
		ServerKeyVersion:   1,
		NewRecoveryKey:     "ZYXW-VUTS-RQPN-MLKJ-HGFE-DCBA",
	})
	if resp.Success {
		t.Fatal("composite accepted a rotated_at past the bound")
	}
	if resp.ErrorCode != string(errs.ErrCodeValidation) {
		t.Fatalf("error_code = %q, want validation_error", resp.ErrorCode)
	}
	// Refused early enough that the entered-key handle was never consumed.
	if exists, _ := deps.RecoveryKeySessions.Status(beginData.EnteredKeyHandle); !exists {
		t.Fatal("a refused date burned the entered recovery key handle")
	}
}
