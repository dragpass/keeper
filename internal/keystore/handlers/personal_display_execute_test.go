package handlers

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/clipboard"
	keepercrypto "github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

func TestPersonalDisplayExecuteSealsOnlyToPreparedFrameAndIsSingleUse(t *testing.T) {
	d, req, binding, frameKey, serverKey := personalDisplayPrepareFixture(t)
	cb := clipboard.NewMemoryClipboard()
	d.Clipboard = cb
	if !HandlePersonalDEKBind(d, binding).Success {
		t.Fatal("provenance fixture bind failed")
	}
	payload, _ := json.Marshal(req)
	prepared := HandlePersonalDisplayPrepare(d, payload)
	if !prepared.Success {
		t.Fatal("personal display prepare failed")
	}
	p := prepared.Data.(proto.PersonalDisplayPrepareResponseData)
	now := d.Now().Unix()
	decision := proto.PersonalDisplayDecision{
		Challenge: p.Challenge, AccountID: binding.Proof.AccountID,
		DeviceID: binding.Proof.DeviceID, TokenID: req.TokenID,
		SessionIssuedAtNanos: 1793440000000000000,
		WrapDigest:           p.WrapDigest, OperationDigest: p.OperationDigest,
		FrameKeyDigest: p.FrameKeyDigest, IssuedAt: now, ExpiresAt: now + 10,
		ServerKeyVersion: 1,
	}
	sign := func(value proto.PersonalDisplayDecision) string {
		sig, err := keepercrypto.SignData(serverKey, proto.PersonalDisplayDecisionCanonical(value))
		if err != nil {
			t.Fatal(err)
		}
		return base64.StdEncoding.EncodeToString(sig)
	}
	decision.Signature = sign(decision)
	request := proto.PersonalDisplayExecuteRequest{Prepare: req, Decision: decision}
	changed := request
	changed.Prepare.Token = "another selected token"
	modified, _ := json.Marshal(changed)
	if HandlePersonalDisplayExecute(d, modified).Success {
		t.Fatal("different ciphertext token produced a personal envelope")
	}
	changed = request
	changed.Decision.Signature = sign(proto.PersonalDisplayDecision{})
	modified, _ = json.Marshal(changed)
	if HandlePersonalDisplayExecute(d, modified).Success {
		t.Fatal("forged personal decision produced an envelope")
	}
	encoded, _ := json.Marshal(request)
	result := HandlePersonalDisplayExecute(d, encoded)
	if !result.Success {
		t.Fatal("valid personal decision failed to execute")
	}
	if cb.WriteCount() != 0 {
		t.Fatal("personal display wrote the OS clipboard")
	}
	response, ok := result.Data.(proto.CurrentGroupDisplayExecuteResponseData)
	if !ok {
		t.Fatal("personal display did not return a frame envelope")
	}
	keeperSPKI, err := base64.StdEncoding.DecodeString(response.KeeperPublicKeySPKIB64)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParsePKIXPublicKey(keeperSPKI)
	if err != nil {
		t.Fatal(err)
	}
	keeperECDH, err := parsed.(*ecdsa.PublicKey).ECDH()
	if err != nil {
		t.Fatal(err)
	}
	frameECDH, err := frameKey.ECDH()
	if err != nil {
		t.Fatal(err)
	}
	shared, err := frameECDH.ECDH(keeperECDH)
	if err != nil {
		t.Fatal(err)
	}
	challenge, _ := base64.RawURLEncoding.DecodeString(response.Challenge)
	opDigest, _ := hex.DecodeString(response.OperationDigest)
	aad := append([]byte("dragpass.personal.display.frame.v1\x00"), opDigest...)
	sealKey, err := hkdf.Key(sha256.New, shared, challenge, string(aad), 32)
	if err != nil {
		t.Fatal(err)
	}
	sealIV, _ := base64.StdEncoding.DecodeString(response.IVB64)
	sealCiphertext, _ := base64.StdEncoding.DecodeString(response.CiphertextB64)
	plaintext, err := keepercrypto.OpenAESGCM(sealKey, sealIV, sealCiphertext, aad)
	if err != nil || !bytes.Equal(plaintext, []byte("frame-only-test-text")) {
		t.Fatal("designated frame could not open the personal envelope")
	}
	if HandlePersonalDisplayExecute(d, encoded).Success {
		t.Fatal("personal decision replay produced another envelope")
	}
}

func TestPersonalDisplayExecuteRefusesSlotReplacementAfterPreparation(t *testing.T) {
	d, req, binding, _, serverKey := personalDisplayPrepareFixture(t)
	if !HandlePersonalDEKBind(d, binding).Success {
		t.Fatal("provenance fixture bind failed")
	}
	preparedJSON, _ := json.Marshal(req)
	prepared := HandlePersonalDisplayPrepare(d, preparedJSON)
	if !prepared.Success {
		t.Fatal("personal display prepare failed")
	}
	p := prepared.Data.(proto.PersonalDisplayPrepareResponseData)
	now := d.Now().Unix()
	decision := proto.PersonalDisplayDecision{
		Challenge: p.Challenge, AccountID: binding.Proof.AccountID,
		DeviceID: binding.Proof.DeviceID, TokenID: req.TokenID,
		SessionIssuedAtNanos: 1793440000000000000,
		WrapDigest:           p.WrapDigest, OperationDigest: p.OperationDigest,
		FrameKeyDigest: p.FrameKeyDigest, IssuedAt: now, ExpiresAt: now + 10,
		ServerKeyVersion: 1,
	}
	signature, err := keepercrypto.SignData(serverKey, proto.PersonalDisplayDecisionCanonical(decision))
	if err != nil {
		t.Fatal(err)
	}
	decision.Signature = base64.StdEncoding.EncodeToString(signature)
	if err := keychain.DeletePersonalDeviceWrappedDEK(d.Store); err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(proto.PersonalDisplayExecuteRequest{Prepare: req, Decision: decision})
	if HandlePersonalDisplayExecute(d, payload).Success {
		t.Fatal("replaced personal slot produced a frame envelope")
	}
}
