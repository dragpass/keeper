//go:build mls && cgo

// The Commit authority rules end to end (chatstate/authority.go, design Q3
// phase 1, Q4, Q16, Q20): three Keepers in one group, and this test standing
// in for ariadne, deciding which Commit wins an epoch and what member set it
// signs for each row.

package dispatch

import (
	"encoding/base64"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/proto"
)

// room is Alice, Bob and Carol at epoch 2: Alice created the conversation
// with Bob, then added Carol.
type room struct {
	*dm
	carol *keeper
}

func newRoom(t *testing.T) *room {
	t.Helper()
	c := newDM(t)
	carol := newKeeper(t, e2eCarol)
	add := commitOf(c.alice.must(proto.MLSCommitBuild, proto.MLSCommitBuildRequest{
		Permit: c.alice.permit(), OrgID: e2eOrg, ConversationID: e2eConv,
		ClientCommitID: c.alice.nextCommitID(), ExpectedEpoch: 1,
		Add: []proto.MLSMemberKeyPackage{carol.keyPackage()}, UserInitiated: true,
	}))
	c.alice.confirm(add.ClientCommitID, proto.MLSCommitOutcomeAccepted, "")
	c.bob.process(c.nextSeq(), 2, add.CommitB64)
	carol.must(proto.MLSJoin, proto.MLSJoinRequest{
		Permit: carol.permit(), OrgID: e2eOrg, ConversationID: e2eConv, WelcomeB64: add.WelcomeB64,
	})
	return &room{dm: c, carol: carol}
}

// userRemove is a Remove a person on this device asked for.
func (k *keeper) userRemove(expected uint64, accounts ...string) proto.MLSCommitResponseData {
	k.t.Helper()
	return commitOf(k.must(proto.MLSCommitBuild, proto.MLSCommitBuildRequest{
		Permit: k.permit(), OrgID: e2eOrg, ConversationID: e2eConv,
		ClientCommitID: k.nextCommitID(), ExpectedEpoch: expected, RemoveAccountIDs: accounts,
		UserInitiated: true,
	}))
}

func (k *keeper) buildRemove(expected uint64, accounts ...string) proto.BaseResponse {
	k.t.Helper()
	return k.call(proto.MLSCommitBuild, proto.MLSCommitBuildRequest{
		Permit: k.permit(), OrgID: e2eOrg, ConversationID: e2eConv,
		ClientCommitID: k.nextCommitID(), ExpectedEpoch: expected, RemoveAccountIDs: accounts,
	})
}

func latchedData(t *testing.T, resp proto.BaseResponse) proto.ChatStateRekeyLatchedData {
	t.Helper()
	if resp.Success || string(resp.ErrorCode) != proto.ChatStateErrorCodeRekeyRequired {
		t.Fatalf("response = %+v; want %s", resp, proto.ChatStateErrorCodeRekeyRequired)
	}
	data, ok := resp.Data.(proto.ChatStateRekeyLatchedData)
	if !ok {
		t.Fatalf("latch response carries %T, not the latch detail", resp.Data)
	}
	return data
}

// Q4's repro. Bob, a plain member, runs a client that tells his own Keeper a
// person asked for the Remove and posts a Commit that declares the member set
// unchanged while it removes Carol's leaf. The server accepts it (the set is the same)
// and signs that set. Alice refuses to apply it and latches the conversation
// read-only, naming the epoch and the committer; nothing is reset, her
// history stays readable, and every later handshake is refused.
func TestMLSAuthority_ASameSetRemoveOfAnotherMemberIsRefusedAndLatches(t *testing.T) {
	r := newRoom(t)
	before := r.send(r.bob, 1, 2, "carol is still here")
	shown := r.alice.decrypt(before)
	assertShown(t, shown, 0, "carol is still here", r.bob, false)

	built := r.bob.userRemove(2, e2eCarol)
	r.bob.confirm(built.ClientCommitID, proto.MLSCommitOutcomeAccepted, "")

	for _, attestation := range []*proto.MLSCommitAttestation{attested(e2eAlice, e2eBob, e2eCarol), nil} {
		req := r.alice.processRequest(r.nextSeq(), 3, built.CommitB64)
		req.CommitAttestation = attestation
		resp := r.alice.call(proto.MLSProcess, req)
		if attestation == nil {
			// Already latched by the first try: the bare code, no detail.
			if resp.Success || string(resp.ErrorCode) != proto.ChatStateErrorCodeRekeyRequired {
				t.Fatalf("a second process = %+v", resp)
			}
			continue
		}
		got := latchedData(t, resp)
		if got.RekeyCause != proto.ChatStateRekeyCauseUnauthorizedCommit || got.RekeyEpoch != 3 ||
			got.RekeyCommitterAccountID != e2eBob || got.RekeyCommitterDeviceID != e2eDevice {
			t.Fatalf("latch detail = %+v", got)
		}
	}

	status := r.alice.status()
	if !status.NeedsRekey || status.RekeyCause != proto.ChatStateRekeyCauseUnauthorizedCommit ||
		status.RekeyEpoch != 3 || status.RekeyCommitterAccountID != e2eBob {
		t.Fatalf("status after the refusal = %+v", status)
	}
	// Read-only, not reset: what she already read is still there.
	assertShown(t, r.alice.decrypt(before), 0, "carol is still here", r.bob, true)
	r.alice.refused(proto.MLSEncrypt, r.alice.encryptRequest(messageID(9), 2, "hello"),
		proto.ChatStateErrorCodeRekeyRequired)
}

// Automation cannot build a Remove of a member or an Add: only a person on
// this device asking for it (R4i), or for a Remove a departure the permit
// names (R3). The Commit authority rules refuse before anything is built.
func TestMLSAuthority_AutomationCannotBuildARemoveOrAnAdd(t *testing.T) {
	r := newRoom(t)
	resp := r.bob.buildRemove(2, e2eCarol)
	if resp.Success || string(resp.ErrorCode) != proto.ChatMLSErrorCodeCommitUnauthorized {
		t.Fatalf("an automated remove of another member = %+v", resp)
	}
	dave := newKeeper(t, "d4444444-4444-4444-8444-444444444444")
	add := r.bob.call(proto.MLSCommitBuild, proto.MLSCommitBuildRequest{
		Permit: r.bob.permit(), OrgID: e2eOrg, ConversationID: e2eConv,
		ClientCommitID: r.bob.nextCommitID(), ExpectedEpoch: 2,
		Add: []proto.MLSMemberKeyPackage{dave.keyPackage()},
	})
	if add.Success || string(add.ErrorCode) != proto.ChatMLSErrorCodeCommitUnauthorized {
		t.Fatalf("an automated add = %+v", add)
	}
	if got := r.bob.status(); got.CommitPending {
		t.Fatal("a refused build left a pending Commit")
	}
	r.bob.refused(proto.MLSCommitBuild, proto.MLSCommitBuildRequest{
		Permit: r.bob.permit(), OrgID: e2eOrg, ConversationID: e2eConv,
		ClientCommitID: r.bob.nextCommitID(), ExpectedEpoch: 2, UpdateSelf: true, UserInitiated: true,
	}, proto.ChatStateErrorCodeInvalidInput)

	// R3: a departure the permit names is anyone's to carry out.
	r.bob.must(proto.MLSCommitBuild, proto.MLSCommitBuildRequest{
		Permit: r.bob.permit(e2eCarol), OrgID: e2eOrg, ConversationID: e2eConv,
		ClientCommitID: r.bob.nextCommitID(), ExpectedEpoch: 2, RemoveAccountIDs: []string{e2eCarol},
	})
}

// An owner's room Remove is applied by every receiver whose row names the new
// member set (R3b), and an R-b Remove by a plain member whose permit names the
// departure (R3), even once the server no longer lists it.
func TestMLSAuthority_AttestedAndDepartedRemovesAreApplied(t *testing.T) {
	r := newRoom(t)
	built := r.alice.userRemove(2, e2eCarol)
	r.alice.confirm(built.ClientCommitID, proto.MLSCommitOutcomeAccepted, "")
	if got := r.bob.processAttested(r.nextSeq(), 3, built.CommitB64, e2eAlice, e2eBob); got.Epoch != 3 {
		t.Fatalf("bob applied the owner's remove at %+v", got)
	}
	if got := r.carol.processAttested(r.nextSeq(), 3, built.CommitB64, e2eAlice, e2eBob); !got.Removed {
		t.Fatalf("carol processed her removal as %+v", got)
	}

	// A signed departure: Bob (a member) removes Alice after she left the
	// org. Carol is gone; Alice's own Keeper is not asked.
	r2 := newRoom(t)
	departed := commitOf(r2.bob.must(proto.MLSCommitBuild, proto.MLSCommitBuildRequest{
		Permit: r2.bob.permit(e2eAlice), OrgID: e2eOrg, ConversationID: e2eConv,
		ClientCommitID: r2.bob.nextCommitID(), ExpectedEpoch: 2, RemoveAccountIDs: []string{e2eAlice},
	}))
	r2.bob.confirm(departed.ClientCommitID, proto.MLSCommitOutcomeAccepted, "")
	// Carol's permit before the Remove named Alice; she latched it then.
	r2.carol.status(e2eAlice)
	r2.carol.refused(proto.MLSEncrypt, r2.carol.encryptRequest(messageID(1), 2, "hi", e2eAlice),
		proto.ChatMLSErrorCodeRotationPending)
	// Now the server has cleared the row and serves no attestation (an old
	// row): R3 still holds through the latch.
	if got := r2.carol.process(r2.nextSeq(), 3, departed.CommitB64); got.Epoch != 3 {
		t.Fatalf("carol applied the departure at %+v", got)
	}
}

// 임시, 정책 미충족 (Q3): a received Add stands on its leaf and trust checks
// alone. Neither the row's attestation nor its absence is authority for it,
// so a server that signs a member set without the account changes nothing.
// This pins the stated limit: any member may Add an account whose leaf
// verifies, until room roles live in the authenticated group context.
func TestMLSAuthority_AReceivedAddStandsOnItsLeafAlone(t *testing.T) {
	c := newDM(t)
	carol := newKeeper(t, e2eCarol)
	add := commitOf(c.alice.must(proto.MLSCommitBuild, proto.MLSCommitBuildRequest{
		Permit: c.alice.permit(), OrgID: e2eOrg, ConversationID: e2eConv,
		ClientCommitID: c.alice.nextCommitID(), ExpectedEpoch: 1,
		Add: []proto.MLSMemberKeyPackage{carol.keyPackage()}, UserInitiated: true,
	}))
	c.alice.confirm(add.ClientCommitID, proto.MLSCommitOutcomeAccepted, "")
	if got := c.bob.processAttested(c.nextSeq(), 2, add.CommitB64, e2eAlice, e2eBob); got.Epoch != 2 {
		t.Fatalf("bob applied the add at %+v", got)
	}
}

// A tampered attestation is a refusal of the request, never read as a
// missing one.
func TestMLSAuthority_AnAttestationThatDoesNotVerifyIsNotAuthorized(t *testing.T) {
	c := newDM(t)
	first := c.alice.buildUpdate(1)
	c.alice.confirm(first.ClientCommitID, proto.MLSCommitOutcomeAccepted, "")
	c.bob.deps.ServerKeyVerifier = refusesSignature{bad: "tampered"}
	req := c.bob.processRequest(c.nextSeq(), 2, first.CommitB64)
	req.CommitAttestation = attested(e2eAlice, e2eBob)
	req.CommitAttestation.Signature = base64.StdEncoding.EncodeToString([]byte("tampered"))
	c.bob.refused(proto.MLSProcess, req, proto.ChatStateErrorCodeNotAuthorized)
	if got := c.bob.status(); got.NeedsRekey || got.Epoch != 1 {
		t.Fatalf("a refused attestation moved the state: %+v", got)
	}
}

// A winner the rules refuse latches the loser instead of being applied.
func TestMLSAuthority_ARefusedWinnerLatchesTheLoser(t *testing.T) {
	r2 := newRoom(t)
	bad := r2.bob.userRemove(2, e2eCarol)
	lost := r2.alice.buildUpdate(2)
	data := latchedData(t, r2.alice.call(proto.MLSCommitConfirm, proto.MLSCommitConfirmRequest{
		Permit: r2.alice.permit(), OrgID: e2eOrg, ConversationID: e2eConv,
		ClientCommitID: lost.ClientCommitID, Outcome: proto.MLSCommitOutcomeSuperseded,
		WinnerCommitB64: bad.CommitB64, WinnerAttestation: attested(e2eAlice, e2eBob, e2eCarol),
	}))
	if data.RekeyCause != proto.ChatStateRekeyCauseUnauthorizedCommit || data.RekeyEpoch != 3 {
		t.Fatalf("latch detail = %+v", data)
	}
}

// refusesSignature accepts every signature but one, so a test can tamper with
// one statement while the permit beside it still verifies.
type refusesSignature struct{ bad string }

func (r refusesSignature) Verify(_ string, sigB64 string, _ uint) error {
	if sigB64 == base64.StdEncoding.EncodeToString([]byte(r.bad)) {
		return errTampered
	}
	return nil
}

var errTampered = errorString("signature does not verify")

type errorString string

func (e errorString) Error() string { return string(e) }
