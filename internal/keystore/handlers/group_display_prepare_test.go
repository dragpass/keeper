package handlers

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

func TestGroupDisplayPrepareBindsCiphertextHandleAndFrameWithoutPlaintext(t *testing.T) {
	f, _, handle := groupDisplayDecisionFixture(t)
	frameKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	frameSPKI, err := x509.MarshalPKIXPublicKey(&frameKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	iv := bytes.Repeat([]byte{3}, 12)
	ciphertext := bytes.Repeat([]byte{4}, 32)
	req := proto.CurrentGroupDisplayPrepareRequest{
		GroupHandle: handle, Token: "⠁⠃⠉",
		IVB64:                 base64.StdEncoding.EncodeToString(iv),
		CiphertextB64:         base64.StdEncoding.EncodeToString(ciphertext),
		FramePublicKeySPKIB64: base64.StdEncoding.EncodeToString(frameSPKI),
		TokenID:               "66666666-6666-4666-8666-666666666666", SessionIssuedAtNanos: 123456789,
	}
	payload, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	resp := HandleGroupDisplayPrepare(f.deps, payload)
	if !resp.Success {
		t.Fatalf("prepare refused: %s", resp.Error)
	}
	data, ok := resp.Data.(proto.CurrentGroupDisplayPrepareResponseData)
	if !ok {
		t.Fatalf("response data type = %T", resp.Data)
	}
	challenge, err := base64.RawURLEncoding.DecodeString(data.Challenge)
	if err != nil || len(challenge) != 32 {
		t.Fatal("prepare did not mint a 32-byte challenge")
	}
	stored, found := f.deps.GroupDisplayChallenges.Peek(data.Challenge, f.clock.now())
	if !found || stored.groupHandle != handle || stored.accountID != f.v.AccountID ||
		stored.tokenID != req.TokenID || stored.sessionStartNanos != req.SessionIssuedAtNanos {
		t.Fatal("prepare did not bind the local operation and session")
	}
	handleBytes, err := base64.StdEncoding.DecodeString(handle)
	if err != nil {
		t.Fatal(err)
	}
	var op proto.CurrentGroupDisplayOperation
	copy(op.Challenge[:], challenge)
	copy(op.GroupHandle[:], handleBytes)
	copy(op.IV[:], iv)
	op.Token = []byte(req.Token)
	op.Ciphertext = ciphertext
	op.FramePublicKeySPKI = frameSPKI
	wantOperation := proto.CurrentGroupDisplayOperationDigest(op)
	wantFrame := sha256.Sum256(frameSPKI)
	if stored.operationDigest != wantOperation || stored.frameKeyDigest != wantFrame ||
		data.OperationDigest != hex.EncodeToString(wantOperation[:]) ||
		data.FrameKeyDigest != hex.EncodeToString(wantFrame[:]) {
		t.Fatal("prepare digests do not bind the exact operation and frame")
	}
	encoded, err := json.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), req.Token) || strings.Contains(string(encoded), "plaintext") {
		t.Fatal("prepare response exposed selected token or plaintext field")
	}
}

func prepareGroupDisplayTestRequest(t *testing.T, handle string) proto.CurrentGroupDisplayPrepareRequest {
	t.Helper()
	frameKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	frameSPKI, err := x509.MarshalPKIXPublicKey(&frameKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return proto.CurrentGroupDisplayPrepareRequest{
		GroupHandle: handle, Token: "⠁⠃⠉",
		IVB64:                 base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{3}, 12)),
		CiphertextB64:         base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{4}, 32)),
		FramePublicKeySPKIB64: base64.StdEncoding.EncodeToString(frameSPKI),
		TokenID:               "66666666-6666-4666-8666-666666666666", SessionIssuedAtNanos: 123456789,
	}
}

func TestGroupDisplayPrepareFeedsOneSignedDecision(t *testing.T) {
	f, decision, handle := groupDisplayDecisionFixture(t)
	req := prepareGroupDisplayTestRequest(t, handle)
	payload, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	resp := HandleGroupDisplayPrepare(f.deps, payload)
	if !resp.Success {
		t.Fatalf("prepare refused: %s", resp.Error)
	}
	data := resp.Data.(proto.CurrentGroupDisplayPrepareResponseData)
	decision.Challenge = data.Challenge
	decision.GroupID = data.GroupID
	decision.DekVersion = data.DekVersion
	decision.GrantDigest = data.GrantDigest
	decision.OperationDigest = data.OperationDigest
	decision.FrameKeyDigest = data.FrameKeyDigest
	decision.Signature = f.sign(t, proto.CurrentGroupDisplayDecisionCanonical(decision))
	if err := verifyAndConsumeCurrentGroupDisplayDecision(f.deps, decision, handle); err != nil {
		t.Fatalf("prepared decision refused: %v", err)
	}
	if err := verifyAndConsumeCurrentGroupDisplayDecision(f.deps, decision, handle); err == nil {
		t.Fatal("prepared decision replay accepted")
	}
}

func TestGroupDisplayPrepareRefusesSignedOutBindingAndInvalidFrame(t *testing.T) {
	f, _, handle := groupDisplayDecisionFixture(t)
	req := prepareGroupDisplayTestRequest(t, handle)
	before := f.deps.GroupDisplayChallenges.Len()
	req.FramePublicKeySPKIB64 = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 91))
	payload, _ := json.Marshal(req)
	if resp := HandleGroupDisplayPrepare(f.deps, payload); resp.Success {
		t.Fatal("invalid frame key minted a challenge")
	}
	if f.deps.GroupDisplayChallenges.Len() != before {
		t.Fatal("invalid frame key changed pending challenges")
	}
	req = prepareGroupDisplayTestRequest(t, handle)
	if _, _, err := keychain.SignOutAccountBinding(f.store); err != nil {
		t.Fatal(err)
	}
	payload, _ = json.Marshal(req)
	if resp := HandleGroupDisplayPrepare(f.deps, payload); resp.Success {
		t.Fatal("signed-out binding minted a challenge")
	}
	if f.deps.GroupDisplayChallenges.Len() != before {
		t.Fatal("signed-out binding changed pending challenges")
	}
}
