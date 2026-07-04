// rotate_request_key_test.go — regression guard.

package handlers

import (
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

func TestRotateRequestKeyPrepare_NoActiveKey(t *testing.T) {
	deps, _, _ := newTestDeps(t)
	resp := HandleRotateRequestKeyPrepare(deps,
		proto.RotateRequestKeyPrepareRequest{ChallengeToken: "abc"})
	if resp.Success {
		t.Fatal("prepare must fail without active key")
	}
	if !strings.Contains(resp.Error, "no active request signing key") {
		t.Errorf("expected not_found error, got %q", resp.Error)
	}
}

func TestRotateRequestKeyPrepare_HappyPath(t *testing.T) {
	deps, _, _ := newTestDeps(t)
	if r := HandleRequestKeyGenerate(deps, proto.RequestKeyGenerateRequest{}); !r.Success {
		t.Fatalf("generate: %s", r.Error)
	}

	resp := HandleRotateRequestKeyPrepare(deps,
		proto.RotateRequestKeyPrepareRequest{ChallengeToken: "challenge-1"})
	if !resp.Success {
		t.Fatalf("prepare failed: %s", resp.Error)
	}
	data, _ := resp.Data.(proto.RotateRequestKeyPrepareResponseData)
	if data.NewPublicKey == "" || data.OldSignature == "" || data.NewSignature == "" {
		t.Fatalf("response missing fields: %+v", data)
	}

	// verify NEW priv was saved into pending slot.
	pendingPriv, err := keychain.GetPendingRequestSigningPrivateKey(deps.Store)
	if err != nil || pendingPriv == "" {
		t.Errorf("pending priv should be saved, err=%v val=%q", err, pendingPriv)
	}

	// OLD signature must verify against the active key.
	oldPubB64, _ := keychain.GetRequestSigningPublicKey(deps.Store)
	oldPub, _ := base64.StdEncoding.DecodeString(oldPubB64)
	oldSig, _ := base64.StdEncoding.DecodeString(data.OldSignature)
	if !ed25519.Verify(ed25519.PublicKey(oldPub), []byte("challenge-1"), oldSig) {
		t.Error("OLD signature does not verify with active public key")
	}

	// NEW signature must verify against NewPublicKey.
	newPub, _ := base64.StdEncoding.DecodeString(data.NewPublicKey)
	newSig, _ := base64.StdEncoding.DecodeString(data.NewSignature)
	if !ed25519.Verify(ed25519.PublicKey(newPub), []byte("challenge-1"), newSig) {
		t.Error("NEW signature does not verify with new public key")
	}
}

func TestRotateRequestKeyPromote_HappyPath(t *testing.T) {
	deps, _, _ := newTestDeps(t)
	if r := HandleRequestKeyGenerate(deps, proto.RequestKeyGenerateRequest{}); !r.Success {
		t.Fatalf("generate: %s", r.Error)
	}
	prep := HandleRotateRequestKeyPrepare(deps,
		proto.RotateRequestKeyPrepareRequest{ChallengeToken: "ch-2"})
	if !prep.Success {
		t.Fatalf("prepare: %s", prep.Error)
	}
	prepData, _ := prep.Data.(proto.RotateRequestKeyPrepareResponseData)

	resp := HandleRotateRequestKeyPromote(deps, proto.RotateRequestKeyPromoteRequest{})
	if !resp.Success {
		t.Fatalf("promote failed: %s", resp.Error)
	}
	data, _ := resp.Data.(proto.RotateRequestKeyPromoteResponseData)
	if !data.Promoted {
		t.Error("promoted should be true")
	}
	if data.ActivePublicKey != prepData.NewPublicKey {
		t.Errorf("active pub %q != prepared new pub %q",
			data.ActivePublicKey, prepData.NewPublicKey)
	}

	// pending slot must be empty.
	if v, _ := keychain.GetPendingRequestSigningPrivateKey(deps.Store); v != "" {
		t.Errorf("pending priv should be cleared after promote, got %q", v)
	}

	// active slot must hold NEW pub.
	activePub, _ := keychain.GetRequestSigningPublicKey(deps.Store)
	if activePub != prepData.NewPublicKey {
		t.Errorf("active pub %q != prepared new pub %q", activePub, prepData.NewPublicKey)
	}

	// After promote, sign_request must work with the new key (indirect regression).
	signResp := HandleSignRequest(deps,
		proto.SignRequestRequest{CanonicalRequest: "post-promote"})
	if !signResp.Success {
		t.Errorf("sign with promoted key failed: %s", signResp.Error)
	}
}

func TestRotateRequestKeyPromote_NoPending(t *testing.T) {
	deps, _, _ := newTestDeps(t)
	if r := HandleRequestKeyGenerate(deps, proto.RequestKeyGenerateRequest{}); !r.Success {
		t.Fatalf("generate: %s", r.Error)
	}
	resp := HandleRotateRequestKeyPromote(deps, proto.RotateRequestKeyPromoteRequest{})
	if resp.Success {
		t.Error("promote without pending must fail")
	}
}

func TestRotateRequestKeyAbort_Idempotent(t *testing.T) {
	deps, _, _ := newTestDeps(t)
	// no pending — first call returns aborted=false.
	resp1 := HandleRotateRequestKeyAbort(deps, proto.RotateRequestKeyAbortRequest{})
	if !resp1.Success {
		t.Fatalf("abort failed: %s", resp1.Error)
	}
	d1, _ := resp1.Data.(proto.RotateRequestKeyAbortResponseData)
	if d1.Aborted {
		t.Error("first abort with no pending should be aborted=false")
	}

	// after prepare, abort returns aborted=true.
	if r := HandleRequestKeyGenerate(deps, proto.RequestKeyGenerateRequest{}); !r.Success {
		t.Fatalf("generate: %s", r.Error)
	}
	if r := HandleRotateRequestKeyPrepare(deps,
		proto.RotateRequestKeyPrepareRequest{ChallengeToken: "ch-3"}); !r.Success {
		t.Fatalf("prepare: %s", r.Error)
	}
	resp2 := HandleRotateRequestKeyAbort(deps, proto.RotateRequestKeyAbortRequest{})
	d2, _ := resp2.Data.(proto.RotateRequestKeyAbortResponseData)
	if !d2.Aborted {
		t.Error("second abort with pending should be aborted=true")
	}
	if v, _ := keychain.GetPendingRequestSigningPrivateKey(deps.Store); v != "" {
		t.Errorf("pending priv should be cleared, got %q", v)
	}
}
