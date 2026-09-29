package keytransparency

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"strings"
	"testing"

	keepercrypto "github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

const monitorAccountID = "00000000-0000-4000-8000-000000000001"

func TestVerifyAccountStatementRotation(t *testing.T) {
	oldKey, err := keepercrypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	newKey, err := keepercrypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	oldPEM := []byte(oldKey.PublicKey)
	newPEM := []byte(newKey.PublicKey)
	rotation := proto.KeyRotationStatement{
		AccountID: monitorAccountID, OldFingerprint: keepercrypto.AccountKeyFingerprint(oldPEM),
		NewFingerprint: keepercrypto.AccountKeyFingerprint(newPEM), RotatedAt: 1700000000,
		Reason:       proto.KeyRotationReasonVoluntary,
		OldPublicKey: base64.StdEncoding.EncodeToString(oldPEM),
		NewPublicKey: base64.StdEncoding.EncodeToString(newPEM),
	}
	oldPrivate, err := keepercrypto.ParsePrivateKey(oldKey.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	newPrivate, err := keepercrypto.ParsePrivateKey(newKey.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	rotation.OldSignature, err = signStatement(t, oldPrivate, rotation.Canonical())
	if err != nil {
		t.Fatal(err)
	}
	rotation.NewSignature, err = signStatement(t, newPrivate, rotation.Canonical())
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := EncodeAccountKeyRotationStatement(rotation)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := VerifyAccountStatement(canonical, monitorAccountID)
	if err != nil {
		t.Fatal(err)
	}
	if verified.SourceType != StatementAccountKeyRotation || verified.Fingerprint != rotation.NewFingerprint || verified.Reason != rotation.Reason || verified.Digest == "" {
		t.Fatalf("unexpected verified statement: %+v", verified)
	}
	if _, err := VerifyAccountStatement(canonical, "00000000-0000-4000-8000-000000000002"); err == nil {
		t.Fatal("accepted a statement for another account")
	}
	parts := strings.Split(string(canonical), "|")
	parts[6] = base64.RawURLEncoding.EncodeToString([]byte("01700000000"))
	if _, err := VerifyAccountStatement([]byte(strings.Join(parts, "|")), monitorAccountID); err == nil {
		t.Fatal("accepted a non-canonical timestamp encoding")
	}
}

func TestVerifyAccountStatementMLSLeaf(t *testing.T) {
	accountKey, err := keepercrypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	private, err := keepercrypto.ParsePrivateKey(accountKey.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafKeyB64 := base64.StdEncoding.EncodeToString(leafKey)
	fingerprint, err := keepercrypto.MLSLeafSignatureKeyFingerprint(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	declaration := proto.MLSLeafDeclaration{
		AccountID: monitorAccountID, DeviceID: "00000000-0000-4000-8000-000000000002",
		SignatureKey: leafKeyB64, SignatureKeyFingerprint: fingerprint,
		NotBefore: 1700000000, NotAfter: 1702592000, Reason: proto.MLSLeafReasonEnroll,
	}
	declaration.Signature, err = signStatement(t, private, declaration.Canonical())
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := EncodeMLSLeafBindingStatement(declaration, accountKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := VerifyAccountStatement(canonical, monitorAccountID)
	if err != nil {
		t.Fatal(err)
	}
	if verified.SourceType != StatementMLSLeafBinding || verified.DeviceID != declaration.DeviceID || verified.Fingerprint != fingerprint {
		t.Fatalf("unexpected verified statement: %+v", verified)
	}
	declaration.Signature = base64.StdEncoding.EncodeToString([]byte("forged"))
	forged, err := EncodeMLSLeafBindingStatement(declaration, accountKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyAccountStatement(forged, monitorAccountID); err == nil {
		t.Fatal("accepted a forged MLS leaf declaration")
	}
}

func signStatement(t *testing.T, privateKey *rsa.PrivateKey, canonical string) (string, error) {
	t.Helper()
	signature, err := keepercrypto.SignData(privateKey, canonical)
	return base64.StdEncoding.EncodeToString(signature), err
}
