package handlers

import (
	"encoding/base64"
	"testing"

	keepercrypto "github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/keytransparency"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

func TestVerifyRotationTransparencyRequiresMatchingProof(t *testing.T) {
	statement := signedRotationStatement(t)
	canonical, err := keytransparency.EncodeAccountKeyRotationStatement(statement)
	if err != nil {
		t.Fatal(err)
	}
	evidence, trust := signedStatementEvidence(t, canonical)

	deps, _, _ := newTestDeps(t)
	deps.KeyTransparency = keytransparency.Gate{Trust: trust}
	if err := verifyRotationTransparency(deps, []proto.KeyRotationStatement{statement}); err == nil {
		t.Fatal("accepted a rotation without transparency evidence")
	}

	statement.TransparencyEvidence = &evidence
	deps, _, _ = newTestDeps(t)
	deps.KeyTransparency = keytransparency.Gate{Trust: trust}
	if err := verifyRotationTransparency(deps, []proto.KeyRotationStatement{statement}); err != nil {
		t.Fatalf("refused a valid witnessed rotation proof: %v", err)
	}
}

func TestVerifyMLSLeafTransparencyRequiresExactStatementProof(t *testing.T) {
	declaration := proto.MLSLeafDeclaration{
		AccountID:               "00000000-0000-4000-8000-000000000001",
		DeviceID:                "00000000-0000-4000-8000-000000000002",
		SignatureKey:            base64.StdEncoding.EncodeToString(make([]byte, 32)),
		SignatureKeyFingerprint: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		NotBefore:               1700000000,
		NotAfter:                1700003600,
		Reason:                  proto.MLSLeafReasonEnroll,
		Signature:               "account-signature",
	}
	accountPublicKey := "-----BEGIN PUBLIC KEY-----\naccount\n-----END PUBLIC KEY-----"
	canonical, err := keytransparency.EncodeMLSLeafBindingStatement(declaration, accountPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	evidence, trust := signedStatementEvidence(t, canonical)
	deps, _, _ := newTestDeps(t)
	deps.KeyTransparency = keytransparency.Gate{Trust: trust}
	if err := verifyMLSLeafTransparency(deps, nil, declaration, accountPublicKey); err == nil {
		t.Fatal("accepted an MLS leaf without transparency evidence")
	}
	if err := verifyMLSLeafTransparency(deps, []proto.KeyTransparencyEvidence{evidence}, declaration, accountPublicKey); err != nil {
		t.Fatalf("refused a valid witnessed MLS leaf proof: %v", err)
	}
	declaration.Reason = proto.MLSLeafReasonRotate
	if err := verifyMLSLeafTransparency(deps, []proto.KeyTransparencyEvidence{evidence}, declaration, accountPublicKey); err == nil {
		t.Fatal("accepted proof for a different MLS leaf statement")
	}
}

func signedRotationStatement(t *testing.T) proto.KeyRotationStatement {
	t.Helper()
	oldPair, err := keepercrypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	newPair, err := keepercrypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	statement := proto.KeyRotationStatement{
		AccountID:      "00000000-0000-4000-8000-000000000001",
		OldFingerprint: keepercrypto.AccountKeyFingerprint([]byte(oldPair.PublicKey)),
		NewFingerprint: keepercrypto.AccountKeyFingerprint([]byte(newPair.PublicKey)),
		RotatedAt:      1700000000,
		Reason:         proto.KeyRotationReasonVoluntary,
		OldPublicKey:   base64.StdEncoding.EncodeToString([]byte(oldPair.PublicKey)),
		NewPublicKey:   base64.StdEncoding.EncodeToString([]byte(newPair.PublicKey)),
	}
	oldPrivate, err := keepercrypto.ParsePrivateKey(oldPair.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	newPrivate, err := keepercrypto.ParsePrivateKey(newPair.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	oldSignature, err := keepercrypto.SignData(oldPrivate, statement.Canonical())
	if err != nil {
		t.Fatal(err)
	}
	newSignature, err := keepercrypto.SignData(newPrivate, statement.Canonical())
	if err != nil {
		t.Fatal(err)
	}
	statement.OldSignature = base64.StdEncoding.EncodeToString(oldSignature)
	statement.NewSignature = base64.StdEncoding.EncodeToString(newSignature)
	return statement
}
