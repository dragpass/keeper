// peer_key_kt_verified_test.go — "pinned" and "proven by the log" are two
// facts, and the wrap path asks for the second (docs/protocol.md, "First peer
// pin with Key Transparency").
//
// With a trust file configured, a pin that no verified log proof stands behind
// (a Welcome tree leaf, an admin key from an org removal statement, a pin
// written before the record existed, a human verification) must not be
// wrapped to on the strength of the pin alone. Each test seeds one such pin and
// checks that the wrap and the evaluation ask for the enrollment proof, accept
// a valid one, remember it across a restart, and bind it to exactly the
// owner, account and key it covered.

package handlers

import (
	"encoding/base64"
	"reflect"
	"testing"
	"time"

	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/keytransparency"
	"github.com/dragpass/keeper/internal/keystore/mls"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

func enrollmentEvidenceFor(t *testing.T, peer trustKey, accountID string) (proto.KeyTransparencyEvidence, *keytransparency.Trust) {
	t.Helper()
	statement, err := keytransparency.EncodeAccountKeyEnrollmentStatement(
		accountID, peer.fingerprint, []byte(peer.pair.PublicKey), mustSignEnrollment(t, peer, accountID),
	)
	if err != nil {
		t.Fatal(err)
	}
	return signedStatementEvidence(t, statement)
}

func seedPin(t *testing.T, store keychain.SecretStore, owner, account string, pin keychain.PeerKeyPin) {
	t.Helper()
	if pin.FirstSeenAt == 0 {
		pin.FirstSeenAt, pin.LastSeenAt = 1700000000, 1700000000
	}
	if err := keychain.SavePeerKeyPin(store, owner, account, pin); err != nil {
		t.Fatal(err)
	}
}

func wrapTo(deps Deps, wrapped string, peer trustKey, evidence *proto.KeyTransparencyEvidence) proto.BaseResponse {
	return HandleDEKRewrapForMember(deps, proto.DEKRewrapForMemberRequest{
		WrappedForMeB64:    wrapped,
		OtherPublicKey:     peer.pair.PublicKey,
		OwnerAccountID:     pinOwnerA,
		OtherAccountID:     pinPeer,
		EnrollmentEvidence: evidence,
	})
}

func TestWrapToAPinNoProofStandsBehindRequiresTheEnrollmentProof(t *testing.T) {
	peer := newTrustKey(t)
	evidence, trust := enrollmentEvidenceFor(t, peer, pinPeer)
	fixture := newWrapFixture(t)
	fixture.deps.KeyTransparency = keytransparency.Gate{Trust: trust}
	seedPin(t, fixture.deps.Store, pinOwnerA, pinPeer, keychain.PeerKeyPin{
		Fingerprint: peer.fingerprint, State: keychain.PeerKeyPinStateTOFU,
	})
	before := mustGetPin(t, fixture.deps, pinOwnerA, pinPeer)

	refused := wrapTo(fixture.deps, fixture.wrapped, peer, nil)
	if refused.Success || refused.ErrorCode != "key_transparency_unverified" {
		t.Fatalf("wrap to an unproven pin = %+v; want key_transparency_unverified", refused)
	}
	if refused.Data != nil {
		t.Fatalf("a refused wrap returned data: %+v", refused.Data)
	}
	if after := mustGetPin(t, fixture.deps, pinOwnerA, pinPeer); !reflect.DeepEqual(after, before) {
		t.Fatalf("the refusal changed the pin: %+v -> %+v", before, after)
	}

	accepted := wrapTo(fixture.deps, fixture.wrapped, peer, &evidence)
	if !accepted.Success {
		t.Fatalf("wrap with a valid enrollment proof = %s (%s)", accepted.Error, accepted.ErrorCode)
	}
	pin := mustGetPin(t, fixture.deps, pinOwnerA, pinPeer)
	if !pin.KeyTransparencyVerified(pinOwnerA, pinPeer) || pin.State != keychain.PeerKeyPinStateTOFU ||
		pin.KeyTransparency.Source != keytransparency.StatementAccountKeyEnrollment {
		t.Fatalf("pin after a proven wrap = %+v (kt %+v)", pin, pin.KeyTransparency)
	}

	// A restart: a new process over the same keyring needs no proof again.
	restarted, _, _ := newTestDeps(t)
	restarted.Store = fixture.deps.Store
	restarted.KeyTransparency = keytransparency.Gate{Trust: trust}
	if again := wrapTo(restarted, fixture.wrapped, peer, nil); !again.Success {
		t.Fatalf("wrap after a restart to a proven pin = %s (%s)", again.Error, again.ErrorCode)
	}
}

func TestEvaluatingAPinNoProofStandsBehindRequiresTheEnrollmentProof(t *testing.T) {
	peer := newTrustKey(t)
	evidence, trust := enrollmentEvidenceFor(t, peer, trustPeerAccount)
	deps, _, store := newTestDeps(t)
	deps.KeyTransparency = keytransparency.Gate{Trust: trust}
	seedPin(t, store, pinOwnerA, trustPeerAccount, keychain.PeerKeyPin{
		Fingerprint: peer.fingerprint, State: keychain.PeerKeyPinStateTOFU,
	})
	request := proto.PeerKeyChainEvaluateRequest{
		OwnerAccountID: pinOwnerA, AccountID: trustPeerAccount, PublicKey: peer.pair.PublicKey,
	}
	if refused := HandlePeerKeyChainEvaluate(deps, request); refused.Success || refused.ErrorCode != "key_transparency_unverified" {
		t.Fatalf("evaluation of an unproven pin = %+v; want key_transparency_unverified", refused)
	}
	request.EnrollmentEvidence = &evidence
	got := evaluateData(t, HandlePeerKeyChainEvaluate(deps, request))
	if got.State != string(keychain.PeerKeyPinStateTOFU) || got.Advanced {
		t.Fatalf("evaluation with a proof = %+v", got)
	}
	if pin := mustGetPin(t, deps, pinOwnerA, trustPeerAccount); !pin.KeyTransparencyVerified(pinOwnerA, trustPeerAccount) {
		t.Fatalf("the proof was not recorded: %+v", pin)
	}
}

// A human's out-of-band check is a different fact from a log proof: the wrap
// still asks for the proof.
func TestAHumanVerifiedPinIsNotALogProof(t *testing.T) {
	peer := newTrustKey(t)
	_, trust := enrollmentEvidenceFor(t, peer, pinPeer)
	fixture := newWrapFixture(t)
	fixture.deps.KeyTransparency = keytransparency.Gate{Trust: trust}
	seedPin(t, fixture.deps.Store, pinOwnerA, pinPeer, keychain.PeerKeyPin{
		Fingerprint: peer.fingerprint, State: keychain.PeerKeyPinStateVerified, VerifiedAt: 1700000000,
	})
	if refused := wrapTo(fixture.deps, fixture.wrapped, peer, nil); refused.Success || refused.ErrorCode != "key_transparency_unverified" {
		t.Fatalf("wrap to a human-verified, unproven pin = %+v", refused)
	}
}

func TestALogProofCountsOnlyForItsOwnOwnerAccountAndKey(t *testing.T) {
	peer := newTrustKey(t)
	other := newTrustKey(t)
	_, trust := enrollmentEvidenceFor(t, peer, pinPeer)
	for name, record := range map[string]keychain.PeerKeyTransparency{
		"another owner":   {OwnerAccountID: pinOwnerB, AccountID: pinPeer, Fingerprint: peer.fingerprint},
		"another account": {OwnerAccountID: pinOwnerA, AccountID: pinPeer2, Fingerprint: peer.fingerprint},
		"another key":     {OwnerAccountID: pinOwnerA, AccountID: pinPeer, Fingerprint: other.fingerprint},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newWrapFixture(t)
			fixture.deps.KeyTransparency = keytransparency.Gate{Trust: trust}
			record.Source = keytransparency.StatementAccountKeyEnrollment
			record.VerifiedAt = 1700000000
			seedPin(t, fixture.deps.Store, pinOwnerA, pinPeer, keychain.PeerKeyPin{
				Fingerprint: peer.fingerprint, State: keychain.PeerKeyPinStateTOFU, KeyTransparency: &record,
			})
			if refused := wrapTo(fixture.deps, fixture.wrapped, peer, nil); refused.Success || refused.ErrorCode != "key_transparency_unverified" {
				t.Fatalf("a record for %s let the wrap through: %+v", name, refused)
			}
		})
	}
}

// With no trust file nothing changes: an unproven pin wraps as before.
func TestWithoutATrustFileAnUnprovenPinWrapsAsBefore(t *testing.T) {
	peer := newTrustKey(t)
	fixture := newWrapFixture(t)
	seedPin(t, fixture.deps.Store, pinOwnerA, pinPeer, keychain.PeerKeyPin{
		Fingerprint: peer.fingerprint, State: keychain.PeerKeyPinStateTOFU,
	})
	if resp := wrapTo(fixture.deps, fixture.wrapped, peer, nil); !resp.Success {
		t.Fatalf("wrap without a trust file = %s (%s)", resp.Error, resp.ErrorCode)
	}
	if pin := mustGetPin(t, fixture.deps, pinOwnerA, pinPeer); pin.KeyTransparency != nil {
		t.Fatalf("no proof was verified, yet the pin records one: %+v", pin.KeyTransparency)
	}
}

// A witnessed rotation carries the proof forward only from a key the log had
// already proven. From an unproven pin it does not, and the wrap is refused
// rather than treating the rotated key as proven.
func TestAWitnessedRotationCarriesTheProofOnlyFromAProvenKey(t *testing.T) {
	statement := signedRotationStatement(t)
	canonical, err := keytransparency.EncodeAccountKeyRotationStatement(statement)
	if err != nil {
		t.Fatal(err)
	}
	evidence, trust := signedStatementEvidence(t, canonical)
	statement.TransparencyEvidence = &evidence
	newPEM, err := base64.StdEncoding.DecodeString(statement.NewPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	account := statement.AccountID

	for _, proven := range []bool{true, false} {
		fixture := newWrapFixture(t)
		fixture.deps.KeyTransparency = keytransparency.Gate{Trust: trust}
		pin := keychain.PeerKeyPin{Fingerprint: statement.OldFingerprint, State: keychain.PeerKeyPinStateTOFU}
		if proven {
			pin.KeyTransparency = &keychain.PeerKeyTransparency{
				OwnerAccountID: pinOwnerA, AccountID: account, Fingerprint: statement.OldFingerprint,
				Source: keytransparency.StatementAccountKeyEnrollment, VerifiedAt: 1700000000,
			}
		}
		seedPin(t, fixture.deps.Store, pinOwnerA, account, pin)
		before := mustGetPin(t, fixture.deps, pinOwnerA, account)
		resp := HandleDEKRewrapForMember(fixture.deps, proto.DEKRewrapForMemberRequest{
			WrappedForMeB64:    fixture.wrapped,
			OtherPublicKey:     string(newPEM),
			OwnerAccountID:     pinOwnerA,
			OtherAccountID:     account,
			RotationStatements: []proto.KeyRotationStatement{statement},
		})
		after := mustGetPin(t, fixture.deps, pinOwnerA, account)
		if proven {
			if !resp.Success {
				t.Fatalf("rotation from a proven key = %s (%s)", resp.Error, resp.ErrorCode)
			}
			if after.State != keychain.PeerKeyPinStateRotated || !after.KeyTransparencyVerified(pinOwnerA, account) ||
				after.KeyTransparency.Source != keytransparency.StatementAccountKeyRotation {
				t.Fatalf("pin after a proven rotation = %+v (kt %+v)", after, after.KeyTransparency)
			}
			continue
		}
		if resp.Success || resp.ErrorCode != "key_transparency_unverified" {
			t.Fatalf("rotation from an unproven key = %+v; want key_transparency_unverified", resp)
		}
		if !reflect.DeepEqual(after, before) {
			t.Fatalf("the refusal changed the pin: %+v -> %+v", before, after)
		}
	}
}

// The MLS side: a Welcome tree leaf is still pinned on first use (MLS
// first-contact identity is not what this solves), but that pin carries no
// proof, so the wrap to it is refused. An entering leaf whose leaf binding the
// log proved records the proof.
func TestATreeLeafPinIsUnprovenAndAnEnteringLeafWithAProofIsProven(t *testing.T) {
	account := newTrustKey(t)
	spec := goodLeafSpec(t, pinPeer, verifyDevice, account)
	declaration := spec.declaration(t)
	payload, err := proto.EncodeMLSLeafExtension(declaration, spec.carriedPEM)
	if err != nil {
		t.Fatal(err)
	}
	leafOf := func(entering bool) mls.Leaf {
		return mls.Leaf{
			Identity: mls.CredentialIdentity(spec.accountID, spec.deviceID), SignatureKey: spec.leafKey,
			Declaration: payload, Entering: entering,
		}
	}
	canonical, err := keytransparency.EncodeMLSLeafBindingStatement(declaration, spec.carriedPEM)
	if err != nil {
		t.Fatal(err)
	}
	evidence, trust := signedStatementEvidence(t, canonical)

	for _, entering := range []bool{false, true} {
		fixture := newWrapFixture(t)
		fixture.deps.KeyTransparency = keytransparency.Gate{Trust: trust}
		fixture.deps.Clock = func() time.Time { return time.Unix(verifyNow, 0) }
		var proofs []proto.KeyTransparencyEvidence
		if entering {
			proofs = []proto.KeyTransparencyEvidence{evidence}
		}
		v := NewMLSLeafVerifier(fixture.deps, pinOwnerA, nil, proofs)
		if err := v.VerifyLeaves([]mls.Leaf{leafOf(entering)}); err != nil {
			t.Fatalf("verify (entering=%v): %v", entering, err)
		}
		if err := v.Commit(); err != nil {
			t.Fatal(err)
		}
		pin := mustGetPin(t, fixture.deps, pinOwnerA, pinPeer)
		if pin.Fingerprint != account.fingerprint || pin.State != keychain.PeerKeyPinStateTOFU {
			t.Fatalf("pin (entering=%v) = %+v", entering, pin)
		}
		if got := pin.KeyTransparencyVerified(pinOwnerA, pinPeer); got != entering {
			t.Fatalf("pin proven = %v (entering=%v): %+v", got, entering, pin.KeyTransparency)
		}
		if !entering {
			if resp := wrapTo(fixture.deps, fixture.wrapped, account, nil); resp.Success || resp.ErrorCode != "key_transparency_unverified" {
				t.Fatalf("wrap to a tree-leaf pin = %+v; want key_transparency_unverified", resp)
			}
		} else if resp := wrapTo(fixture.deps, fixture.wrapped, account, nil); !resp.Success {
			t.Fatalf("wrap to a proven entering-leaf pin = %s (%s)", resp.Error, resp.ErrorCode)
		}
	}
}

// pin_get reports the proof state so the client knows to fetch the proof.
func TestPinGetReportsWhetherALogProofStandsBehindThePin(t *testing.T) {
	peer := newTrustKey(t)
	deps, _, store := newTestDeps(t)
	seedPin(t, store, pinOwnerA, pinPeer, keychain.PeerKeyPin{
		Fingerprint: peer.fingerprint, State: keychain.PeerKeyPinStateTOFU,
		KeyTransparency: &keychain.PeerKeyTransparency{
			OwnerAccountID: pinOwnerA, AccountID: pinPeer, Fingerprint: peer.fingerprint,
			Source: keytransparency.StatementAccountKeyEnrollment, VerifiedAt: 1700000000,
		},
	})
	seedPin(t, store, pinOwnerA, pinPeer2, keychain.PeerKeyPin{
		Fingerprint: crypto.AccountKeyFingerprint([]byte("x")), State: keychain.PeerKeyPinStateTOFU,
	})
	for account, want := range map[string]bool{pinPeer: true, pinPeer2: false} {
		resp := HandlePeerKeyPinGet(deps, proto.PeerKeyPinGetRequest{OwnerAccountID: pinOwnerA, AccountID: account})
		data, ok := resp.Data.(proto.PeerKeyPinGetResponseData)
		if !resp.Success || !ok || data.Pin == nil {
			t.Fatalf("pin_get(%s) = %+v", account, resp)
		}
		if data.Pin.KeyTransparencyVerified != want {
			t.Fatalf("pin_get(%s).key_transparency_verified = %v; want %v", account, data.Pin.KeyTransparencyVerified, want)
		}
	}
}
