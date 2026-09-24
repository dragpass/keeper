//go:build mls && cgo

// The Commit authority rules end to end (chatstate/authority.go, design Q3
// phase 1, Q4, Q16, Q20): three Keepers in one group, and this test standing
// in for ariadne, deciding which Commit wins an epoch and what member set it
// signs for each row.

package dispatch

import (
	"encoding/base64"
	"slices"
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

// blockedData is the sync block a CHAT_MLS_ROW_REFUSED answer carries (N3).
func blockedData(t *testing.T, resp proto.BaseResponse) proto.MLSSyncBlock {
	t.Helper()
	if resp.Success || string(resp.ErrorCode) != proto.ChatMLSErrorCodeRowRefused {
		t.Fatalf("response = %+v; want %s", resp, proto.ChatMLSErrorCodeRowRefused)
	}
	data, ok := resp.Data.(*proto.MLSSyncBlock)
	if !ok || data == nil {
		t.Fatalf("row refusal carries %T, not the block", resp.Data)
	}
	return *data
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
// and signs that set. Alice refuses to apply it and stops at that epoch (N3),
// naming the epoch and the committer; the conversation is not latched,
// nothing is reset, her history stays readable, a new message is refused,
// and the same row is refused again each time it is served.
func TestMLSAuthority_ASameSetRemoveOfAnotherMemberIsRefusedAndBlocks(t *testing.T) {
	r := newRoom(t)
	before := r.send(r.bob, 1, 2, "carol is still here")
	shown := r.alice.decrypt(before)
	assertShown(t, shown, 0, "carol is still here", r.bob, false)

	built := r.bob.userRemove(2, e2eCarol)
	r.bob.confirm(built.ClientCommitID, proto.MLSCommitOutcomeAccepted, "")

	for _, attestation := range []*proto.MLSCommitAttestation{attested(e2eAlice, e2eBob, e2eCarol), nil} {
		req := r.alice.processRequest(r.nextSeq(), 3, built.CommitB64)
		req.CommitAttestation = attestation
		got := blockedData(t, r.alice.call(proto.MLSProcess, req))
		if got.Cause != proto.ChatStateRekeyCauseUnauthorizedCommit || got.Epoch != 3 ||
			got.CommitterAccountID != e2eBob || got.CommitterDeviceID != e2eDevice || got.CommitSHA256 == "" {
			t.Fatalf("block = %+v", got)
		}
	}

	status := r.alice.status()
	if status.NeedsRekey || status.SyncBlocked == nil || status.SyncBlocked.Epoch != 3 ||
		status.SyncBlocked.CommitterAccountID != e2eBob || status.Epoch != 2 {
		t.Fatalf("status after the refusal = %+v", status)
	}
	// Not reset: what she already read is still there, and nothing new goes
	// out on top of a state nobody agreed on.
	assertShown(t, r.alice.decrypt(before), 0, "carol is still here", r.bob, true)
	r.alice.refused(proto.MLSEncrypt, r.alice.encryptRequest(messageID(9), 2, "hello"),
		proto.ChatMLSErrorCodeSyncBlocked)
}

// N3: a blocked row is not a dead end. Another, valid Commit for the same
// epoch (here Alice's own key update, accepted by the server once the bad row
// is gone) is applied and clears the block, and sends work again. The block
// never moved the confirmed state: the valid Commit applies to the epoch the
// refused one was built on.
func TestMLSAuthority_AValidCommitForTheBlockedEpochClearsTheBlock(t *testing.T) {
	r := newRoom(t)
	bad := r.bob.userRemove(2, e2eCarol)
	r.bob.confirm(bad.ClientCommitID, proto.MLSCommitOutcomeAccepted, "")
	blockedData(t, r.alice.call(proto.MLSProcess, r.alice.processRequestAttested(r.nextSeq(), 3, bad.CommitB64,
		e2eAlice, e2eBob, e2eCarol)))

	good := r.carol.buildUpdate(2)
	r.carol.confirm(good.ClientCommitID, proto.MLSCommitOutcomeAccepted, "")
	if got := r.alice.process(r.nextSeq(), 3, good.CommitB64); got.Epoch != 3 {
		t.Fatalf("alice applied the valid commit for the blocked epoch as %+v", got)
	}
	if st := r.alice.status(); st.SyncBlocked != nil || st.NeedsRekey || st.Epoch != 3 {
		t.Fatalf("status after the valid commit = %+v", st)
	}
	r.alice.must(proto.MLSEncrypt, r.alice.encryptRequest(messageID(1), 3, "back in step"))
}

// Automation cannot build a Remove of a member or an Add in a legacy room:
// only a person on this device asking for it (legacy_temporary), or for a
// Remove a signed statement. The Commit authority rules refuse before anything
// is built.
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

	// The permit naming a departure is no longer enough (wave 5a): only the
	// org admin's signed statement makes it anyone's to carry out.
	r.bob.refused(proto.MLSCommitBuild, proto.MLSCommitBuildRequest{
		Permit: r.bob.permit(e2eCarol), OrgID: e2eOrg, ConversationID: e2eConv,
		ClientCommitID: r.bob.nextCommitID(), ExpectedEpoch: 2, RemoveAccountIDs: []string{e2eCarol},
	}, proto.ChatMLSErrorCodeCommitUnauthorized)
	r.bob.must(proto.MLSCommitBuild, proto.MLSCommitBuildRequest{
		Permit: r.bob.permit(e2eCarol), OrgID: e2eOrg, ConversationID: e2eConv,
		ClientCommitID: r.bob.nextCommitID(), ExpectedEpoch: 2, RemoveAccountIDs: []string{e2eCarol},
		OrgRemovalStatements: []proto.MLSOrgRemovalStatement{orgRemoval(newKeeper(t, e2eAdmin), e2eCarol)},
	})
}

// In a legacy room an owner's Remove is applied by every receiver whose row
// names the new member set (R3b, legacy_temporary), and an R-b Remove by a
// plain member carrying the org admin's statement even once the server no
// longer lists the departure.
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
	// org, on the org admin's statement. Alice's own Keeper is not asked.
	r2 := newRoom(t)
	departed := commitOf(r2.bob.must(proto.MLSCommitBuild, proto.MLSCommitBuildRequest{
		Permit: r2.bob.permit(e2eAlice), OrgID: e2eOrg, ConversationID: e2eConv,
		ClientCommitID: r2.bob.nextCommitID(), ExpectedEpoch: 2, RemoveAccountIDs: []string{e2eAlice},
		OrgRemovalStatements: []proto.MLSOrgRemovalStatement{orgRemoval(newKeeper(t, e2eAdmin), e2eAlice)},
	}))
	r2.bob.confirm(departed.ClientCommitID, proto.MLSCommitOutcomeAccepted, "")
	// Carol's permit before the Remove named Alice; she latched it then.
	r2.carol.status(e2eAlice)
	r2.carol.refused(proto.MLSEncrypt, r2.carol.encryptRequest(messageID(1), 2, "hi", e2eAlice),
		proto.ChatMLSErrorCodeRotationPending)
	// Now the server has cleared the row and serves no attestation (an old
	// row): the statement inside the Commit is what carol verifies.
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

// Q16's repro. The server serves Bob, for an epoch he already applied, a
// Commit other than the one he applied there. He latches fork and merges
// nothing; a redelivery of the Commit he did apply is only already applied.
func TestMLSFork_AnotherCommitForAConfirmedEpochLatchesFork(t *testing.T) {
	c := newDM(t)
	first := c.alice.buildUpdate(1)
	c.alice.confirm(first.ClientCommitID, proto.MLSCommitOutcomeAccepted, "")
	c.bob.processAttested(c.nextSeq(), 2, first.CommitB64, e2eAlice, e2eBob)

	c.bob.refused(proto.MLSProcess, c.bob.processRequest(c.nextSeq(), 2, first.CommitB64),
		proto.ChatMLSErrorCodeEpochStale)

	other := c.alice.buildUpdate(2)
	got := latchedData(t, c.bob.call(proto.MLSProcess, c.bob.processRequest(c.nextSeq(), 2, other.CommitB64)))
	if got.RekeyCause != proto.ChatStateRekeyCauseFork || got.RekeyEpoch != 2 || got.RekeyCommitterAccountID != "" {
		t.Fatalf("fork latch detail = %+v", got)
	}
	status := c.bob.status()
	if !status.NeedsRekey || status.RekeyCause != proto.ChatStateRekeyCauseFork || status.RekeyEpoch != 2 {
		t.Fatalf("status after the fork = %+v", status)
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

// Q20: a Commit that lost its epoch reports what the winner did, so the app
// can stop when the winner touched the accounts it was about.
func TestMLSAuthority_ALostRaceReportsWhatTheWinnerDid(t *testing.T) {
	r := newRoom(t)
	winner := r.bob.userRemove(2, e2eCarol)
	loser := r.alice.userRemove(2, e2eCarol)
	r.bob.confirm(winner.ClientCommitID, proto.MLSCommitOutcomeAccepted, "")
	got := r.alice.must(proto.MLSCommitConfirm, proto.MLSCommitConfirmRequest{
		Permit: r.alice.permit(), OrgID: e2eOrg, ConversationID: e2eConv,
		ClientCommitID: loser.ClientCommitID, Outcome: proto.MLSCommitOutcomeSuperseded,
		WinnerCommitB64: winner.CommitB64, WinnerAttestation: attested(e2eAlice, e2eBob),
	}).Data.(proto.MLSCommitConfirmResponseData)
	if got.Epoch != 3 || !slices.Equal(got.WinnerRemovedAccountIDs, []string{e2eCarol}) ||
		len(got.WinnerAddedAccountIDs) != 0 {
		t.Fatalf("confirm superseded = %+v", got)
	}

	// A winner the rules refuse is not applied (N3): the loser's own pending
	// Commit, which lost the epoch either way, is dropped, the confirmed state
	// stays, and the conversation stops at the winner's epoch.
	r2 := newRoom(t)
	bad := r2.bob.userRemove(2, e2eCarol)
	lost := r2.alice.buildUpdate(2)
	data := blockedData(t, r2.alice.call(proto.MLSCommitConfirm, proto.MLSCommitConfirmRequest{
		Permit: r2.alice.permit(), OrgID: e2eOrg, ConversationID: e2eConv,
		ClientCommitID: lost.ClientCommitID, Outcome: proto.MLSCommitOutcomeSuperseded,
		WinnerCommitB64: bad.CommitB64, WinnerAttestation: attested(e2eAlice, e2eBob, e2eCarol),
	}))
	if data.Cause != proto.ChatStateRekeyCauseUnauthorizedCommit || data.Epoch != 3 {
		t.Fatalf("block = %+v", data)
	}
	if st := r2.alice.status(); st.CommitPending || st.NeedsRekey || st.Epoch != 2 || st.SyncBlocked == nil {
		t.Fatalf("status after the refused winner = %+v", st)
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

func (k *keeper) processRequestAttested(seq, epoch uint64, commitB64 string, members ...string) proto.MLSProcessRequest {
	req := k.processRequest(seq, epoch, commitB64)
	req.CommitAttestation = attested(members...)
	return req
}
