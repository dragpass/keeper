package handlers

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/clipboard"
	keepercrypto "github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

func TestGroupDisplayExecuteSealsOnlyToPreparedFrame(t *testing.T) {
	f, decision, handle := groupDisplayDecisionFixture(t)
	frameKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	frameSPKI, err := x509.MarshalPKIXPublicKey(&frameKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("frame-only-secret")
	tokenAAD := groupDisplayTestAAD(f)
	iv, ciphertext, err := keepercrypto.SealAESGCM(rand.Reader, mustHex(t, f.v.GroupDEKHex), plaintext, tokenAAD)
	if err != nil {
		t.Fatal(err)
	}
	req := proto.CurrentGroupDisplayPrepareRequest{
		GroupHandle: handle, Token: "selected-ciphertext-token",
		TokenAADB64: base64.StdEncoding.EncodeToString(tokenAAD),
		IVB64:       base64.StdEncoding.EncodeToString(iv), CiphertextB64: base64.StdEncoding.EncodeToString(ciphertext),
		FramePublicKeySPKIB64: base64.StdEncoding.EncodeToString(frameSPKI),
		TokenID:               decision.TokenID, SessionIssuedAtNanos: "123456789",
	}
	prepared, _ := json.Marshal(req)
	prep := HandleGroupDisplayPrepare(f.deps, prepared)
	if !prep.Success {
		t.Fatalf("prepare: %s", prep.Error)
	}
	p := prep.Data.(proto.CurrentGroupDisplayPrepareResponseData)
	decision.Challenge, decision.GroupID, decision.DekVersion = p.Challenge, p.GroupID, p.DekVersion
	decision.GrantDigest, decision.OperationDigest, decision.FrameKeyDigest = p.GrantDigest, p.OperationDigest, p.FrameKeyDigest
	decision.Signature = f.sign(t, proto.CurrentGroupDisplayDecisionCanonical(decision))
	tamperedPrepare := req
	tamperedPrepare.Token = "another-selected-token"
	tampered, _ := json.Marshal(proto.CurrentGroupDisplayExecuteRequest{Prepare: tamperedPrepare, Decision: decision})
	if denied := HandleGroupDisplayExecute(f.deps, tampered); denied.Success {
		t.Fatal("changed selected token produced an envelope")
	}
	badDecision := decision
	badDecision.Signature = f.sign(t, "another decision")
	tampered, _ = json.Marshal(proto.CurrentGroupDisplayExecuteRequest{Prepare: req, Decision: badDecision})
	if denied := HandleGroupDisplayExecute(f.deps, tampered); denied.Success {
		t.Fatal("invalid server signature produced an envelope")
	}
	execute, _ := json.Marshal(proto.CurrentGroupDisplayExecuteRequest{Prepare: req, Decision: decision})
	resp := HandleGroupDisplayExecute(f.deps, execute)
	if !resp.Success {
		t.Fatalf("execute: %s", resp.Error)
	}
	encoded, _ := json.Marshal(resp)
	if bytes.Contains(encoded, plaintext) || strings.Contains(string(encoded), "plaintext") {
		t.Fatal("execute response exposed plaintext")
	}
	if f.deps.Clipboard.(*clipboard.MemoryClipboard).WriteCount() != 0 {
		t.Fatal("display wrote the OS clipboard")
	}
	sealed := resp.Data.(proto.CurrentGroupDisplayExecuteResponseData)
	keeperSPKI, err := base64.StdEncoding.DecodeString(sealed.KeeperPublicKeySPKIB64)
	if err != nil {
		t.Fatal(err)
	}
	parsedKeeperKey, err := x509.ParsePKIXPublicKey(keeperSPKI)
	if err != nil {
		t.Fatal(err)
	}
	keeperECDH, err := parsedKeeperKey.(*ecdsa.PublicKey).ECDH()
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
	challenge, err := base64.RawURLEncoding.DecodeString(sealed.Challenge)
	if err != nil {
		t.Fatal(err)
	}
	opDigest, err := hex.DecodeString(sealed.OperationDigest)
	if err != nil {
		t.Fatal(err)
	}
	aad := append([]byte("dragpass.group.display.frame.v1\x00"), opDigest...)
	frameSealKey, err := hkdf.Key(sha256.New, shared, challenge, string(aad), 32)
	if err != nil {
		t.Fatal(err)
	}
	sealIV, err := base64.StdEncoding.DecodeString(sealed.IVB64)
	if err != nil {
		t.Fatal(err)
	}
	sealCiphertext, err := base64.StdEncoding.DecodeString(sealed.CiphertextB64)
	if err != nil {
		t.Fatal(err)
	}
	got, err := keepercrypto.OpenAESGCM(frameSealKey, sealIV, sealCiphertext, aad)
	if err != nil || !bytes.Equal(got, plaintext) {
		t.Fatal("only the prepared frame key must open the envelope")
	}
	if again := HandleGroupDisplayExecute(f.deps, execute); again.Success {
		t.Fatal("signed decision replay produced a second envelope")
	}
}
