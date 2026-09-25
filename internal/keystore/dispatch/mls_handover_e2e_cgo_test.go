//go:build mls && cgo

// Device succession (design §0.3 policy 1, Q1, Q2) end to end through the
// dispatcher: Alice, Bob and Carol in a room, and Bob2, a new machine of Bob's
// account that got the account key (a password login would give it that) and
// nothing else. The test stands in for ariadne: it accepts Bob2's rotate and
// lists the takeover in the permits it signs.

package dispatch

import (
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/dragpass/keeper/internal/keystore/chatstate"
	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// takeoverRoom is the room with Bob2's rotate accepted and listed for every
// member, and Bob2's KeyPackage.
func takeoverRoom(t *testing.T) (*room, *keeper, proto.MLSLeafDeclaration, proto.MLSMemberKeyPackage) {
	t.Helper()
	r := newRoom(t)
	oldBob, _, err := keychain.GetMLSLeafNewest(r.alice.store, r.alice.id, r.bob.id)
	if err != nil {
		t.Fatal(err)
	}
	bob2 := newTakeoverKeeper(t, r.bob, e2eDevice2)
	decl := bob2.declare(proto.MLSLeafReasonRotate, oldBob.NotBefore+60)
	listed := []proto.ChatStateLeafReplacement{{AccountID: r.bob.id, NewSignatureKeyFP: decl.SignatureKeyFingerprint}}
	r.alice.replacing, r.bob.replacing, r.carol.replacing, bob2.replacing = listed, listed, listed, listed
	return r, bob2, decl, bob2.keyPackage()
}

// handoverFor is k, the device whose leaf holds the seat, approving decl.
func (k *keeper) handoverFor(decl proto.MLSLeafDeclaration) proto.MLSLeafHandover {
	k.t.Helper()
	return k.must(proto.ActionMLSLeafHandoverSign, proto.MLSLeafHandoverSignRequest{
		AccountID: k.id, NewDeclaration: decl, ExpiresAt: time.Now().Unix() + proto.MLSLeafHandoverMaxSeconds,
	}).Data.(proto.MLSLeafHandoverSignResponseData).Handover
}

func approved(kp proto.MLSMemberKeyPackage, h proto.MLSLeafHandover) proto.MLSReplaceMember {
	m := replaceOf(kp)
	m.Handover = &h
	return m
}

// Q1's repro. A device with the account key and no approval from Bob's old
// device takes Bob's seat. Alice's automation replaces Bob's leaf with Bob2's
// on the permit's word alone, and Carol applies a replace nobody on Bob's
// old device approved. Both must be refused: Alice builds nothing, and Carol
// refuses the crafted Commit and latches unauthorized_commit.
func TestMLSHandover_ATakeoverWithoutTheOldDevicesApprovalIsRefused(t *testing.T) {
	r, _, _, kp := takeoverRoom(t)

	resp := r.alice.buildReplace(2, replaceOf(kp))
	if resp.Success || string(resp.ErrorCode) != proto.ChatMLSErrorCodeCommitUnauthorized {
		t.Fatalf("an unapproved replace = %+v; want %s", resp, proto.ChatMLSErrorCodeCommitUnauthorized)
	}
	if got := r.alice.status(); got.CommitPending || got.Epoch != 2 {
		t.Fatalf("a refused replace left %+v", got)
	}
	// The receiving half, a modified client posting such a Commit, is
	// mls.TestSuccession_AReceiverRefusesAnUnapprovedTakeover.
}

// The approved takeover: Bob's old device signs the handover for Bob2's
// declaration, Alice's replace carries it, Carol applies it, Bob's old device
// learns it was removed, Bob2 joins, and messages cross with Bob2 named as
// the sender. Nothing before the join is readable on Bob2.
func TestMLSHandover_AnApprovedTakeoverIsBuiltAppliedAndJoined(t *testing.T) {
	r, bob2, decl, kp := takeoverRoom(t)
	listed := r.alice.replacing
	r.alice.replacing = nil
	before := r.send(r.alice, 1, 2, "before the takeover")
	r.alice.replacing = listed
	h := r.bob.handoverFor(decl)
	if h.OldDeviceID != e2eDevice || h.NewDeviceID != e2eDevice2 || h.NewSignatureKeyFP != decl.SignatureKeyFingerprint ||
		h.ExpiresAt-h.IssuedAt > proto.MLSLeafHandoverMaxSeconds {
		t.Fatalf("handover = %+v", h)
	}

	built := commitOf(r.alice.must(proto.MLSCommitBuild, proto.MLSCommitBuildRequest{
		Permit: r.alice.permit(), OrgID: e2eOrg, ConversationID: e2eConv,
		ClientCommitID: r.alice.nextCommitID(), ExpectedEpoch: 2, Replace: []proto.MLSReplaceMember{approved(kp, h)},
	}))
	r.alice.confirm(built.ClientCommitID, proto.MLSCommitOutcomeAccepted, "")
	if got := r.carol.process(r.nextSeq(), 3, built.CommitB64); got.Epoch != 3 {
		t.Fatalf("carol applied the approved takeover as %+v", got)
	}
	if got := r.bob.process(r.nextSeq(), 3, built.CommitB64); !got.Removed {
		t.Fatalf("bob's old device processed the takeover as %+v", got)
	}
	bob2.must(proto.MLSJoin, proto.MLSJoinRequest{
		Permit: bob2.permit(), OrgID: e2eOrg, ConversationID: e2eConv, WelcomeB64: built.WelcomeB64,
	})
	r.alice.replacing, r.carol.replacing, bob2.replacing = nil, nil, nil

	fromBob2 := r.send(bob2, 2, 3, "new laptop")
	got := r.carol.decrypt(fromBob2)
	if plaintextOf(t, got.PlaintextB64[0]) != "new laptop" || got.Items[0].SenderDeviceID != e2eDevice2 {
		t.Fatalf("carol read %+v", got.Items[0])
	}
	// No history moves: the message from before the join is not readable,
	// and is reported as before the join rather than as a failure.
	old := bob2.decrypt(before)
	if old.Items[0].State != proto.MLSDisplayItemStateBeforeJoin {
		t.Fatalf("bob2 sees the pre-join message as %+v", old.Items[0])
	}
}

// The old device refuses to approve anything it cannot vouch for: a
// declaration its account key did not sign, one for itself, one for another
// account, an enroll, and a request whose window has closed or lies too far
// out. Each is CHAT_MLS_HANDOVER_INVALID and signs nothing.
func TestMLSHandover_TheOldDeviceRefusesWhatItCannotVouchFor(t *testing.T) {
	r, bob2, decl, _ := takeoverRoom(t)
	now := time.Now().Unix()
	sign := func(d proto.MLSLeafDeclaration, expires int64) proto.BaseResponse {
		return r.bob.call(proto.ActionMLSLeafHandoverSign, proto.MLSLeafHandoverSignRequest{
			AccountID: r.bob.id, NewDeclaration: d, ExpiresAt: expires,
		})
	}
	expect := func(name string, resp proto.BaseResponse) {
		t.Helper()
		if resp.Success || string(resp.ErrorCode) != proto.ChatMLSErrorCodeHandoverInvalid {
			t.Fatalf("%s: %+v; want %s", name, resp, proto.ChatMLSErrorCodeHandoverInvalid)
		}
	}

	expect("closed window", sign(decl, now-1))
	expect("window too far out", sign(decl, now+proto.MLSLeafHandoverMaxSeconds+3600))

	// A server that swaps in Mallory's device under Bob's name: the
	// declaration is signed by another account key.
	mallory := newKeeper(t, "e5555555-5555-4555-8555-555555555555")
	forged := decl
	forged.Signature = mallory.signAsAccount(forged.Canonical())
	expect("another account key", sign(forged, now+300))

	// Bob's own device named as the new one.
	self := decl
	self.DeviceID = e2eDevice
	self.Signature = r.bob.signAsAccount(self.Canonical())
	expect("this device itself", sign(self, now+300))

	enroll := decl
	enroll.Reason = proto.MLSLeafReasonEnroll
	enroll.Signature = r.bob.signAsAccount(enroll.Canonical())
	expect("an enroll", sign(enroll, now+300))

	// A device with no active leaf has nothing to approve with.
	resp := bob2.call(proto.ActionMLSLeafHandoverSign, proto.MLSLeafHandoverSignRequest{
		AccountID: bob2.id, NewDeclaration: decl, ExpiresAt: now + 300,
	})
	if resp.Success {
		t.Fatalf("the new device approved its own takeover: %+v", resp)
	}
}

// A handover that does not fit the replace is refused as such at build and
// builds nothing: one for another new leaf, and one signed by a key that is
// not the removed leaf's (Bob2 approving itself).
func TestMLSHandover_AHandoverThatDoesNotFitIsRefusedAtBuild(t *testing.T) {
	r, bob2, decl, kp := takeoverRoom(t)
	good := r.bob.handoverFor(decl)

	other := good
	other.NewSignatureKeyFP = strings.Repeat("ab", 32)
	resp := r.alice.buildReplace(2, approved(kp, other))
	if resp.Success || string(resp.ErrorCode) != proto.ChatMLSErrorCodeHandoverInvalid {
		t.Fatalf("a handover for another leaf = %+v", resp)
	}

	self := good
	self.Signature = base64.StdEncoding.EncodeToString(bob2.signAsLeaf(t, good))
	resp = r.alice.buildReplace(2, approved(kp, self))
	if resp.Success || string(resp.ErrorCode) != proto.ChatMLSErrorCodeHandoverInvalid {
		t.Fatalf("a handover the new leaf signed = %+v", resp)
	}
	if got := r.alice.status(); got.CommitPending || got.Epoch != 2 {
		t.Fatalf("refused replaces left %+v", got)
	}
}

// signAsAccount signs canonical with k's account key, the way a declaration
// is signed.
func (k *keeper) signAsAccount(canonical string) string {
	k.t.Helper()
	pem, err := keychain.GetPrivateKey(k.store)
	if err != nil {
		k.t.Fatal(err)
	}
	priv, err := crypto.ParsePrivateKey(pem)
	if err != nil {
		k.t.Fatal(err)
	}
	sig, err := crypto.SignData(priv, canonical)
	if err != nil {
		k.t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(sig)
}

// signAsLeaf signs h's canonical with k's own active leaf key.
func (k *keeper) signAsLeaf(t *testing.T, h proto.MLSLeafHandover) []byte {
	t.Helper()
	leaf, found, err := keychain.GetMLSLeafKey(k.store)
	if err != nil || !found {
		t.Fatalf("no active leaf: %v", err)
	}
	return ed25519.Sign(ed25519.PrivateKey(leaf.SecretKey), []byte(chatstate.LeafHandoverCanonical(chatstate.LeafHandover{
		AccountID: h.AccountID, OldDeviceID: h.OldDeviceID, OldFingerprint: h.OldSignatureKeyFP,
		NewDeviceID: h.NewDeviceID, NewFingerprint: h.NewSignatureKeyFP, IssuedAt: h.IssuedAt, ExpiresAt: h.ExpiresAt,
	})))
}

// A rejoin re-seats the leaf key the account already holds in the group; it
// is never a way to hand the seat to another key. Bob2, holding Bob's account
// key, signs a perfectly valid rejoin request for its own leaf, and a Bob
// whose leaf rotated since signs one for his new key: both would replace the
// dead leaf with another key without the old leaf's handover, so Alice's
// Keeper builds neither.
func TestMLSHandover_ARejoinUnderAnotherLeafKeyBuildsNothing(t *testing.T) {
	alice, bob, _ := deadLeafRoom(t)

	bob2 := newTakeoverKeeper(t, bob, e2eDevice2)
	bob2.declare(proto.MLSLeafReasonRotate, time.Now().Unix()+60)
	resp := alice.buildRejoin(1, proto.MLSRejoinMember{
		AccountID: e2eBob, DeviceID: e2eDevice2, KeyPackageB64: bob2.keyPackage().KeyPackageB64,
		Request: bob2.rejoinRequest(),
	})
	if resp.Success || string(resp.ErrorCode) != proto.ChatMLSErrorCodeCommitUnauthorized {
		t.Fatalf("a rejoin under another device's key = %+v", resp)
	}

	bob.declare(proto.MLSLeafReasonRotate, time.Now().Unix()+120)
	resp = alice.buildRejoin(1, proto.MLSRejoinMember{
		AccountID: e2eBob, DeviceID: e2eDevice, KeyPackageB64: bob.keyPackage().KeyPackageB64,
		Request: bob.rejoinRequest(),
	})
	if resp.Success || string(resp.ErrorCode) != proto.ChatMLSErrorCodeCommitUnauthorized {
		t.Fatalf("a rejoin under a rotated key = %+v", resp)
	}
	if got := alice.status(); got.CommitPending || got.Epoch != 1 {
		t.Fatalf("refused rejoins left %+v", got)
	}
}
