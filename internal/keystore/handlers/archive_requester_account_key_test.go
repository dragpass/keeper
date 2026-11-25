package handlers

import (
	"errors"
	"reflect"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/keytransparency"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

func TestArchiveRequesterAccountKeyRequiresLogTrust(t *testing.T) {
	deps, _, _ := newTestDeps(t)
	peer := newTrustKey(t)
	req := proto.PeerKeyChainEvaluateRequest{OwnerAccountID: pinOwnerA, AccountID: pinPeer, PublicKey: peer.pair.PublicKey, RequireTransparency: true}
	refused := HandlePeerKeyChainEvaluate(deps, req)
	if refused.Success {
		t.Fatal("unconfigured first contact accepted a key without a log proof")
	}
	if _, err := keychain.GetPeerKeyPin(deps.Store, pinOwnerA, pinPeer); !errors.Is(err, keychain.ErrSecretNotFound) {
		t.Fatal("refused evaluation wrote a pin")
	}
	evidence, trust := enrollmentEvidenceFor(t, peer, pinPeer)
	deps.KeyTransparency = keytransparency.Gate{Trust: trust}
	req.EnrollmentEvidence = &evidence
	result := HandlePeerKeyChainEvaluate(deps, req)
	if !result.Success || !mustGetPin(t, deps, pinOwnerA, pinPeer).KeyTransparencyVerified(pinOwnerA, pinPeer) {
		t.Fatal("valid enrollment failed")
	}
}

func TestArchiveRequesterAccountKeyAfterRotation(t *testing.T) {
	old, current := newTrustKey(t), newTrustKey(t)
	enrollment, err := keytransparency.EncodeAccountKeyEnrollmentStatement(pinPeer, old.fingerprint, []byte(old.pair.PublicKey), mustSignEnrollment(t, old, pinPeer))
	if err != nil {
		t.Fatal(err)
	}
	link := statementFor(t, old, current, pinPeer, proto.KeyRotationReasonVoluntary)
	rotation, err := keytransparency.EncodeAccountKeyRotationStatement(link)
	if err != nil {
		t.Fatal(err)
	}
	proofs, trust := signedAccountEvidence(t, enrollment, rotation)
	link.TransparencyEvidence = &proofs[1]
	req := proto.PeerKeyChainEvaluateRequest{RequireTransparency: true, OwnerAccountID: pinOwnerA, AccountID: pinPeer, PublicKey: current.pair.PublicKey, EnrollmentEvidence: &proofs[0], RotationStatements: []proto.KeyRotationStatement{link}}
	for _, tc := range []struct {
		name string
		pin  string
		want bool
	}{
		{"first contact", "", true},
		{"existing unproven enrollment key", old.fingerprint, true},
		{"existing unproven current key", current.fingerprint, true},
		{"unrelated pin", newTrustKey(t).fingerprint, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			deps, _, _ := newTestDeps(t)
			deps.KeyTransparency = keytransparency.Gate{Trust: trust}
			if tc.pin != "" {
				seedPin(t, deps.Store, pinOwnerA, pinPeer, keychain.PeerKeyPin{Fingerprint: tc.pin, State: keychain.PeerKeyPinStateTOFU})
			}
			r := HandlePeerKeyChainEvaluate(deps, req)
			data, _ := r.Data.(proto.PeerKeyChainEvaluateResponseData)
			if r.Success != tc.want || data.TransparencyVerified != tc.want {
				t.Fatalf("verified=%v want %v, error code %s", data.TransparencyVerified, tc.want, r.ErrorCode)
			}
			got := mustGetPin(t, deps, pinOwnerA, pinPeer)
			if tc.want && (got.Fingerprint != current.fingerprint || !got.KeyTransparencyVerified(pinOwnerA, pinPeer)) {
				t.Fatal("missing verified current key")
			}
			if !tc.want && got.Fingerprint != tc.pin {
				t.Fatal("changed an unrelated pin")
			}
		})
	}
	for _, tc := range []struct {
		name   string
		change func(*proto.PeerKeyChainEvaluateRequest)
	}{
		{"missing enrollment", func(r *proto.PeerKeyChainEvaluateRequest) { r.EnrollmentEvidence = nil }},
		{"missing rotation proof", func(r *proto.PeerKeyChainEvaluateRequest) { r.RotationStatements[0].TransparencyEvidence = nil }},
		{"substituted rotation proof", func(r *proto.PeerKeyChainEvaluateRequest) { r.RotationStatements[0].TransparencyEvidence = &proofs[0] }},
		{"substituted enrollment", func(r *proto.PeerKeyChainEvaluateRequest) { r.EnrollmentEvidence = &proofs[1] }},
		{"invalid signature", func(r *proto.PeerKeyChainEvaluateRequest) {
			r.RotationStatements[0].OldSignature = r.RotationStatements[0].NewSignature
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			deps, _, _ := newTestDeps(t)
			deps.KeyTransparency = keytransparency.Gate{Trust: trust}
			seedPin(t, deps.Store, pinOwnerA, pinPeer, keychain.PeerKeyPin{Fingerprint: old.fingerprint, State: keychain.PeerKeyPinStateVerified})
			before := mustGetPin(t, deps, pinOwnerA, pinPeer)
			altered := req
			altered.RotationStatements = []proto.KeyRotationStatement{link}
			tc.change(&altered)
			if r := HandlePeerKeyChainEvaluate(deps, altered); r.Success || r.Data != nil {
				t.Fatal("invalid chain accepted")
			}
			if !reflect.DeepEqual(mustGetPin(t, deps, pinOwnerA, pinPeer), before) {
				t.Fatal("invalid chain changed the pin")
			}
		})
	}
}

func TestArchiveRequesterAccountKeyRejectsUnexplainedChange(t *testing.T) {
	deps, _, _ := newTestDeps(t)
	first, other := newTrustKey(t), newTrustKey(t)
	enrollment, trust := enrollmentEvidenceFor(t, first, pinPeer)
	deps.KeyTransparency = keytransparency.Gate{Trust: trust}
	req := proto.PeerKeyChainEvaluateRequest{RequireTransparency: true, OwnerAccountID: pinOwnerA, AccountID: pinPeer, PublicKey: first.pair.PublicKey, EnrollmentEvidence: &enrollment}
	if !HandlePeerKeyChainEvaluate(deps, req).Success {
		t.Fatal("initial evaluation failed")
	}
	req.PublicKey = other.pair.PublicKey
	req.EnrollmentEvidence = nil
	r := HandlePeerKeyChainEvaluate(deps, req)
	if r.Success || r.Data != nil {
		t.Fatal("required log verification returned success for an unexplained change")
	}
	if mustGetPin(t, deps, pinOwnerA, pinPeer).Fingerprint != first.fingerprint {
		t.Fatal("refusal replaced prior pin")
	}
}

func TestArchiveRequesterAccountKeyRequiresEnrollmentLineage(t *testing.T) {
	peer := newTrustKey(t)
	enrollment, trust := enrollmentEvidenceFor(t, peer, pinPeer)
	for _, source := range []string{keytransparency.StatementMLSLeafBinding, keytransparency.StatementAccountKeyRotation} {
		t.Run(source, func(t *testing.T) {
			deps, _, _ := newTestDeps(t)
			deps.KeyTransparency = keytransparency.Gate{Trust: trust}
			seedPin(t, deps.Store, pinOwnerA, pinPeer, keychain.PeerKeyPin{Fingerprint: peer.fingerprint, State: keychain.PeerKeyPinStateVerified, KeyTransparency: peerKeyProofRecord(deps, pinOwnerA, pinPeer, peer.fingerprint, source)})
			req := proto.PeerKeyChainEvaluateRequest{RequireTransparency: true, OwnerAccountID: pinOwnerA, AccountID: pinPeer, PublicKey: peer.pair.PublicKey}
			if r := HandlePeerKeyChainEvaluate(deps, req); r.Success {
				t.Fatal("accepted a pin whose enrollment was never proven")
			}
			req.EnrollmentEvidence = &enrollment
			if r := HandlePeerKeyChainEvaluate(deps, req); !r.Success {
				t.Fatal("refused the matching signed enrollment")
			}
			req.EnrollmentEvidence = nil
			if r := HandlePeerKeyChainEvaluate(deps, req); !r.Success {
				t.Fatal("lost the authenticated enrollment")
			}
		})
	}
}

func TestArchiveRequesterAccountKeyContinuesFromProvenMiddlePin(t *testing.T) {
	first, middle, last := newTrustKey(t), newTrustKey(t), newTrustKey(t)
	links := []proto.KeyRotationStatement{
		statementFor(t, first, middle, pinPeer, proto.KeyRotationReasonVoluntary),
		statementFor(t, middle, last, pinPeer, proto.KeyRotationReasonRecovery),
	}
	var canonical [][]byte
	for _, link := range links {
		encoded, err := keytransparency.EncodeAccountKeyRotationStatement(link)
		if err != nil {
			t.Fatal(err)
		}
		canonical = append(canonical, encoded)
	}
	proofs, trust := signedAccountEvidence(t, canonical...)
	for i := range links {
		links[i].TransparencyEvidence = &proofs[i]
	}
	deps, _, _ := newTestDeps(t)
	deps.KeyTransparency = keytransparency.Gate{Trust: trust}
	middleProof := peerKeyProofRecord(deps, pinOwnerA, pinPeer, middle.fingerprint, keytransparency.StatementAccountKeyRotation)
	middleProof.EnrollmentTrust = trust.ConfigDigest
	seedPin(t, deps.Store, pinOwnerA, pinPeer, keychain.PeerKeyPin{Fingerprint: middle.fingerprint, State: keychain.PeerKeyPinStateRotated, KeyTransparency: middleProof})
	req := proto.PeerKeyChainEvaluateRequest{RequireTransparency: true, OwnerAccountID: pinOwnerA, AccountID: pinPeer, PublicKey: last.pair.PublicKey, RotationStatements: links}
	ended := evaluateData(t, HandlePeerKeyChainEvaluate(deps, req))
	if !ended.TransparencyVerified || !ended.Advanced || ended.Fingerprint != last.fingerprint {
		t.Fatal("failed to advance proven intermediate pin")
	}
	req.RotationStatements = nil
	if repeated := evaluateData(t, HandlePeerKeyChainEvaluate(deps, req)); !repeated.TransparencyVerified || repeated.Advanced {
		t.Fatal("lost enrollment ancestry on repeat")
	}
}

func TestArchiveRequesterAccountKeyOnTrustChange(t *testing.T) {
	deps, _, _ := newTestDeps(t)
	peer := newTrustKey(t)
	enrollment, trust := enrollmentEvidenceFor(t, peer, pinPeer)
	deps.KeyTransparency = keytransparency.Gate{Trust: trust}
	r := proto.PeerKeyChainEvaluateRequest{RequireTransparency: true, OwnerAccountID: pinOwnerA, AccountID: pinPeer, PublicKey: peer.pair.PublicKey, EnrollmentEvidence: &enrollment}
	if !HandlePeerKeyChainEvaluate(deps, r).Success {
		t.Fatal("original proof failed")
	}
	other := *trust
	other.ConfigDigest = "another-test-trust-config"
	deps.KeyTransparency.Trust = &other
	r.EnrollmentEvidence = nil
	if HandlePeerKeyChainEvaluate(deps, r).Success {
		t.Fatal("trusted cached enrollment under a different log")
	}
}
