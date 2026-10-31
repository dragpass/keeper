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
	"testing"

	"github.com/dragpass/keeper/config"
	"github.com/dragpass/keeper/internal/keystore/clipboard"
	keepercrypto "github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

func TestAuditGroupDisplayRequiresTableBoundOnlineDecision(t *testing.T) {
	f := newAuditFixture(t)
	f.deps.GroupDisplayChallenges = NewGroupDisplayChallengeStore()
	deviceID := "55555555-5555-4555-8555-555555555555"
	if err := f.store.Set(config.Service, config.DeviceID, deviceID); err != nil {
		t.Fatal(err)
	}
	frameKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	frameSPKI, err := x509.MarshalPKIXPublicKey(&frameKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	permit := f.permit(t, nil)
	req := proto.AuditGroupDisplayPrepareRequest{
		GroupHandle: f.handle, Token: "audit-token", IVB64: base64.StdEncoding.EncodeToString(mustHex(t, f.v.IVHex)),
		CiphertextB64:         base64.StdEncoding.EncodeToString(mustHex(t, f.v.CiphertextHex)),
		FramePublicKeySPKIB64: base64.StdEncoding.EncodeToString(frameSPKI),
		TokenID:               "66666666-6666-4666-8666-666666666666", SessionIssuedAtNanos: "123456789",
		OrgID: f.v.OrgID, GroupID: f.v.GroupID, DekVersion: f.v.DekVersion,
		TableID: f.v.TableID, TableB64: base64.StdEncoding.EncodeToString(f.table), Permit: permit,
	}
	prepared := HandleAuditGroupDisplayPrepare(f.deps, payloadOf(t, req))
	if !prepared.Success {
		t.Fatalf("prepare: %s", prepared.Error)
	}
	p := prepared.Data.(proto.AuditGroupDisplayPrepareResponseData)
	decision := proto.AuditGroupDisplayDecision{CurrentGroupDisplayDecision: proto.CurrentGroupDisplayDecision{
		Challenge: p.Challenge, AccountID: f.v.AccountID, DeviceID: deviceID,
		TokenID: req.TokenID, SessionIssuedAtNanos: 123456789,
		GroupID: p.GroupID, DekVersion: p.DekVersion, GrantDigest: p.GrantDigest,
		OperationDigest: p.OperationDigest, FrameKeyDigest: p.FrameKeyDigest,
		IssuedAt: f.clock.now().Unix() - 1, ExpiresAt: f.clock.now().Unix() + 9, ServerKeyVersion: 1,
	}, TableID: p.TableID, TableDigest: p.TableDigest}
	decision.Signature = f.sign(t, proto.AuditGroupDisplayDecisionCanonical(decision))
	wrongSignature := decision
	wrongSignature.Signature = f.sign(t, "different decision")
	if denied := HandleAuditGroupDisplayExecute(f.deps, payloadOf(t, proto.AuditGroupDisplayExecuteRequest{Prepare: req, Decision: wrongSignature})); denied.Success {
		t.Fatal("invalid API signature produced an envelope")
	}
	changedPermit := req
	changedPermit.Permit.Signature = f.sign(t, "different permit")
	if denied := HandleAuditGroupDisplayExecute(f.deps, payloadOf(t, proto.AuditGroupDisplayExecuteRequest{Prepare: changedPermit, Decision: decision})); denied.Success {
		t.Fatal("changed permit produced an envelope")
	}
	bad := decision
	bad.TableDigest = hex.EncodeToString(bytes.Repeat([]byte{8}, sha256.Size))
	bad.Signature = f.sign(t, proto.AuditGroupDisplayDecisionCanonical(bad))
	if resp := HandleAuditGroupDisplayExecute(f.deps, payloadOf(t, proto.AuditGroupDisplayExecuteRequest{Prepare: req, Decision: bad})); resp.Success {
		t.Fatal("changed table digest produced an envelope")
	}
	resp := HandleAuditGroupDisplayExecute(f.deps, payloadOf(t, proto.AuditGroupDisplayExecuteRequest{Prepare: req, Decision: decision}))
	if !resp.Success {
		t.Fatalf("execute: %s", resp.Error)
	}
	encoded, _ := json.Marshal(resp)
	if bytes.Contains(encoded, []byte(f.v.Plaintext)) || f.deps.Clipboard.(*clipboard.MemoryClipboard).WriteCount() != 0 {
		t.Fatal("audit display exposed plaintext outside its frame envelope")
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
	if err != nil || !bytes.Equal(got, []byte(f.v.Plaintext)) {
		t.Fatal("prepared frame could not open the audit envelope")
	}
	if replay := HandleAuditGroupDisplayExecute(f.deps, payloadOf(t, proto.AuditGroupDisplayExecuteRequest{Prepare: req, Decision: decision})); replay.Success {
		t.Fatal("audit decision replay produced a second envelope")
	}
}
