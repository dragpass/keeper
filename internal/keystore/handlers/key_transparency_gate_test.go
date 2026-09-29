package handlers

import (
	"encoding/base64"
	"testing"

	keepercrypto "github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/keytransparency"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

func TestFirstPeerPinRequiresItsEnrollmentProofWhenTransparencyIsConfigured(t *testing.T) {
	accountID := pinPeer
	peer := newTrustKey(t)
	statement, err := keytransparency.EncodeAccountKeyEnrollmentStatement(
		accountID,
		peer.fingerprint,
		[]byte(peer.pair.PublicKey),
		mustSignEnrollment(t, peer, accountID),
	)
	if err != nil {
		t.Fatal(err)
	}
	evidence, trust := signedStatementEvidence(t, statement)

	fixture := newWrapFixture(t)
	fixture.deps.KeyTransparency = keytransparency.Gate{Trust: trust}
	request := proto.DEKRewrapForMemberRequest{
		WrappedForMeB64: fixture.wrapped,
		OtherPublicKey:  peer.pair.PublicKey,
		OwnerAccountID:  pinOwnerA,
		OtherAccountID:  accountID,
	}
	if refused := HandleDEKRewrapForMember(fixture.deps, request); refused.Success || refused.ErrorCode != "key_transparency_unverified" {
		t.Fatalf("first observation without proof = %+v, want key_transparency_unverified", refused)
	}
	if _, err := keychain.GetPeerKeyPin(fixture.deps.Store, pinOwnerA, accountID); err == nil {
		t.Fatal("refused first observation wrote a TOFU pin")
	}

	request.EnrollmentEvidence = &evidence
	accepted := HandleDEKRewrapForMember(fixture.deps, request)
	if !accepted.Success {
		t.Fatalf("valid witnessed enrollment refused: %s (%s)", accepted.Error, accepted.ErrorCode)
	}
	pin := mustGetPin(t, fixture.deps, pinOwnerA, accountID)
	if pin.Fingerprint != peer.fingerprint || pin.State != keychain.PeerKeyPinStateTOFU {
		t.Fatalf("pin = %+v, want the witnessed account key", pin)
	}
}

func TestFirstPeerPinRejectsEnrollmentForAnotherAccountOrKey(t *testing.T) {
	peer := newTrustKey(t)
	other := newTrustKey(t)
	for _, target := range []struct {
		name      string
		accountID string
		publicKey string
	}{
		{name: "another account", accountID: "00000000-0000-4000-8000-000000000099", publicKey: peer.pair.PublicKey},
		{name: "another key", accountID: pinPeer, publicKey: other.pair.PublicKey},
	} {
		t.Run(target.name, func(t *testing.T) {
			statement, err := keytransparency.EncodeAccountKeyEnrollmentStatement(
				pinPeer,
				peer.fingerprint,
				[]byte(peer.pair.PublicKey),
				mustSignEnrollment(t, peer, pinPeer),
			)
			if err != nil {
				t.Fatal(err)
			}
			evidence, trust := signedStatementEvidence(t, statement)
			fixture := newWrapFixture(t)
			fixture.deps.KeyTransparency = keytransparency.Gate{Trust: trust}
			response := HandleDEKRewrapForMember(fixture.deps, proto.DEKRewrapForMemberRequest{
				WrappedForMeB64:    fixture.wrapped,
				OtherPublicKey:     target.publicKey,
				OwnerAccountID:     pinOwnerA,
				OtherAccountID:     target.accountID,
				EnrollmentEvidence: &evidence,
			})
			if response.Success || response.ErrorCode != "key_transparency_unverified" {
				t.Fatalf("accepted mismatched enrollment: %+v", response)
			}
			if _, err := keychain.GetPeerKeyPin(fixture.deps.Store, pinOwnerA, target.accountID); err == nil {
				t.Fatal("mismatched enrollment wrote a TOFU pin")
			}
		})
	}
}

func TestPeerKeyFirstEvaluationRequiresMatchingEnrollmentProof(t *testing.T) {
	peer := newTrustKey(t)
	statement, err := keytransparency.EncodeAccountKeyEnrollmentStatement(
		trustPeerAccount,
		peer.fingerprint,
		[]byte(peer.pair.PublicKey),
		mustSignEnrollment(t, peer, trustPeerAccount),
	)
	if err != nil {
		t.Fatal(err)
	}
	evidence, trust := signedStatementEvidence(t, statement)
	deps, _, _ := newTestDeps(t)
	deps.KeyTransparency = keytransparency.Gate{Trust: trust}
	request := proto.PeerKeyChainEvaluateRequest{
		OwnerAccountID: pinOwnerA,
		AccountID:      trustPeerAccount,
		PublicKey:      peer.pair.PublicKey,
	}
	if refused := HandlePeerKeyChainEvaluate(deps, request); refused.Success || refused.ErrorCode != "key_transparency_unverified" {
		t.Fatalf("first evaluation without proof = %+v, want key_transparency_unverified", refused)
	}
	if _, err := keychain.GetPeerKeyPin(deps.Store, pinOwnerA, trustPeerAccount); err == nil {
		t.Fatal("refused first evaluation wrote a TOFU pin")
	}

	request.EnrollmentEvidence = &evidence
	accepted := evaluateData(t, HandlePeerKeyChainEvaluate(deps, request))
	if accepted.State != string(keychain.PeerKeyPinStateTOFU) || !accepted.Advanced {
		t.Fatalf("evaluation = %+v, want an advanced TOFU pin", accepted)
	}
}

func mustSignEnrollment(t *testing.T, peer trustKey, accountID string) []byte {
	t.Helper()
	canonical := proto.AccountKeyEnrollmentCanonical(accountID, peer.fingerprint)
	signature, err := keepercrypto.SignData(peer.priv, canonical)
	if err != nil {
		t.Fatal(err)
	}
	return signature
}

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
