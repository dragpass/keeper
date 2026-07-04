// rotate_keypair_promote_test.go — HandleRotateUserKeypairPromote +
// integration RoundTrip 가드.
package handlers

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/verifier"
)

func TestApp_HandleRotateUserKeypairPromote_VerifyFailedShortCircuits(t *testing.T) {
	deps, log, _ := newTestDepsFailVerify(t, errors.New("server signature verification failed: stub"))

	resp := HandleRotateUserKeypairPromote(deps, proto.RotateUserKeypairPromoteRequest{
		ConfirmationToken:     "any-token",
		ConfirmationPayload:   "any-payload",
		ConfirmationSignature: "any-sig",
	})

	if resp.Success {
		t.Fatalf("expected failure when ServerKeyVerifier rejects")
	}
	if !strings.Contains(resp.Error, "server signature verification failed") {
		t.Fatalf("error must include verifier failure prefix, got %q", resp.Error)
	}

	// Did not even reach pending lookup — regression guard that verify rejects first.
	if log.Contains("pending → active") {
		t.Fatalf("must not promote on verify failure: %v", log.Messages())
	}
}

func TestHandleRotateUserKeypairPromote_Success(t *testing.T) {
	deps, _, store := newTestDeps(t)
	oldPub, _ := seedActiveKeypairForRotateTest(t, store)

	prep := HandleRotateUserKeypairPrepare(deps, proto.RotateUserKeypairPrepareRequest{
		ChallengeToken:  "rotate-challenge-003",
		ServerSignature: "any",
	})
	if !prep.Success {
		t.Fatalf("prepare: %s", prep.Error)
	}
	prepData := prep.Data.(proto.RotateUserKeypairPrepareResponseData)
	newPub := prepData.NewPublicKey

	promote := HandleRotateUserKeypairPromote(deps, proto.RotateUserKeypairPromoteRequest{
		ConfirmationToken:     "rotate-confirm-003",
		ConfirmationPayload:   futureRotateConfirmationPayloadForTest(t, "rotate-confirm-003", newPub),
		ConfirmationSignature: "any",
	})
	if !promote.Success {
		t.Fatalf("promote: %s", promote.Error)
	}
	promData := promote.Data.(proto.RotateUserKeypairPromoteResponseData)
	if !promData.Promoted {
		t.Errorf("Promoted should be true")
	}
	if promData.ActivePublicKey != newPub {
		t.Errorf("active pub mismatch: got %q want %q", promData.ActivePublicKey, newPub)
	}
	if promData.ActivePublicKey == oldPub {
		t.Errorf("active pub unchanged after promote")
	}

	// verify pending slot was cleared
	if _, err := keychain.GetPendingPrivateKey(store); err == nil {
		t.Errorf("pending priv should be cleared after promote")
	}
}

func TestHandleRotateUserKeypairPromote_RejectsBadServerSig(t *testing.T) {
	// Stage 1 (prepare) must pass with OK verify; stage 2 (promote) must
	// reject. Two deps separate the verify branches (both share the same store).
	prepDeps, _, store := newTestDeps(t)
	promoteDeps := prepDeps
	promoteDeps.ServerKeyVerifier = verifier.AlwaysFailVerifier{Err: errors.New("server signature verification failed: stub")}

	seedActiveKeypairForRotateTest(t, store)

	prep := HandleRotateUserKeypairPrepare(prepDeps, proto.RotateUserKeypairPrepareRequest{
		ChallengeToken:  "rotate-challenge-004",
		ServerSignature: "any",
	})
	if !prep.Success {
		t.Fatalf("prepare: %s", prep.Error)
	}

	promote := HandleRotateUserKeypairPromote(promoteDeps, proto.RotateUserKeypairPromoteRequest{
		ConfirmationToken:     "rotate-confirm-004",
		ConfirmationPayload:   futureRotateConfirmationPayloadForTest(t, "rotate-confirm-004", "pending-public-key"),
		ConfirmationSignature: "bad",
	})
	if promote.Success {
		t.Fatalf("expected promote to reject bad confirmation signature")
	}
	// pending must be preserved (retry possible)
	if _, err := keychain.GetPendingPrivateKey(store); err != nil {
		t.Errorf("pending priv should be preserved on rejected promote: %v", err)
	}
}

func TestHandleRotateUserKeypairPromote_RejectsPendingPublicKeyMismatch(t *testing.T) {
	deps, _, store := newTestDeps(t)
	seedActiveKeypairForRotateTest(t, store)

	prep := HandleRotateUserKeypairPrepare(deps, proto.RotateUserKeypairPrepareRequest{
		ChallengeToken:  "rotate-challenge-mismatch",
		ServerSignature: "any",
	})
	if !prep.Success {
		t.Fatalf("prepare: %s", prep.Error)
	}

	resp := HandleRotateUserKeypairPromote(deps, proto.RotateUserKeypairPromoteRequest{
		ConfirmationToken:     "rotate-confirm-mismatch",
		ConfirmationPayload:   futureRotateConfirmationPayloadForTest(t, "rotate-confirm-mismatch", "different-pending-public-key"),
		ConfirmationSignature: "any",
	})
	if resp.Success {
		t.Fatalf("expected promote to reject confirmation for different pending key")
	}
	if !strings.Contains(resp.Error, "pending public key does not match") {
		t.Fatalf("expected pending key mismatch error, got %q", resp.Error)
	}
}

func TestHandleRotateUserKeypairPromote_RejectsExpiredConfirmationPayload(t *testing.T) {
	deps, _, store := newTestDeps(t)
	deps.Clock = func() time.Time { return time.Unix(200, 0) }
	seedActiveKeypairForRotateTest(t, store)

	prep := HandleRotateUserKeypairPrepare(deps, proto.RotateUserKeypairPrepareRequest{
		ChallengeToken:  "rotate-challenge-expired",
		ServerSignature: "any",
	})
	if !prep.Success {
		t.Fatalf("prepare: %s", prep.Error)
	}
	prepData := prep.Data.(proto.RotateUserKeypairPrepareResponseData)

	resp := HandleRotateUserKeypairPromote(deps, proto.RotateUserKeypairPromoteRequest{
		ConfirmationToken:     "rotate-confirm-expired",
		ConfirmationPayload:   rotateConfirmationPayloadForTest(t, "rotate-confirm-expired", prepData.NewPublicKey, 199),
		ConfirmationSignature: "any",
	})
	if resp.Success {
		t.Fatalf("expected promote to reject expired confirmation")
	}
	if !strings.Contains(resp.Error, "confirmation expired") {
		t.Fatalf("expected expiry error, got %q", resp.Error)
	}
}

func TestHandleRotateUserKeypairPromote_NoPending(t *testing.T) {
	deps, _, store := newTestDeps(t)
	seedActiveKeypairForRotateTest(t, store)
	// attempt promote with pending empty

	resp := HandleRotateUserKeypairPromote(deps, proto.RotateUserKeypairPromoteRequest{
		ConfirmationToken:     "rotate-confirm-005",
		ConfirmationPayload:   futureRotateConfirmationPayloadForTest(t, "rotate-confirm-005", "pending-public-key"),
		ConfirmationSignature: "any",
	})
	if resp.Success {
		t.Fatalf("expected failure when no pending keypair")
	}
}

func TestRotateUserKeypair_RoundTrip_NewKeypairUsable(t *testing.T) {
	// prepare → promote → verify the new active priv can sign arbitrary data.
	deps, _, store := newTestDeps(t)
	seedActiveKeypairForRotateTest(t, store)

	prep := HandleRotateUserKeypairPrepare(deps, proto.RotateUserKeypairPrepareRequest{
		ChallengeToken:  "rotate-roundtrip-001",
		ServerSignature: "any",
	})
	if !prep.Success {
		t.Fatalf("prepare: %s", prep.Error)
	}
	prepData := prep.Data.(proto.RotateUserKeypairPrepareResponseData)

	// promote
	promote := HandleRotateUserKeypairPromote(deps, proto.RotateUserKeypairPromoteRequest{
		ConfirmationToken:     "rotate-roundtrip-confirm-001",
		ConfirmationPayload:   futureRotateConfirmationPayloadForTest(t, "rotate-roundtrip-confirm-001", prepData.NewPublicKey),
		ConfirmationSignature: "any",
	})
	if !promote.Success {
		t.Fatalf("promote: %s", promote.Error)
	}

	// Sign arbitrary data with new active priv → verification with NewPublicKey must pass
	activePrivBuf, err := GetPrivateKeySecure(store)
	if err != nil {
		t.Fatalf("GetPrivateKeySecure: %v", err)
	}
	defer activePrivBuf.Destroy()

	dataB64, err := SignDataSecure(activePrivBuf, "hello")
	if err != nil {
		t.Fatalf("SignDataSecure: %v", err)
	}
	newPub, err := crypto.ParsePublicKey(prepData.NewPublicKey)
	if err != nil {
		t.Fatalf("ParsePublicKey: %v", err)
	}
	sigBytes, err := base64.StdEncoding.DecodeString(dataB64)
	if err != nil {
		t.Fatalf("decode sig: %v", err)
	}
	if err := crypto.VerifySignature(newPub, "hello", sigBytes); err != nil {
		t.Errorf("active priv after promote should match prepData.NewPublicKey: %v", err)
	}
}
