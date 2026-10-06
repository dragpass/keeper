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

	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/mls/mlsadversary"
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
	if resp.Success || string(resp.ErrorCode) != string(errs.ErrCodeChatMLSRowRefused) {
		t.Fatalf("response = %+v; want %s", resp, string(errs.ErrCodeChatMLSRowRefused))
	}
	data, ok := resp.Data.(*proto.MLSSyncBlock)
	if !ok || data == nil {
		t.Fatalf("row refusal carries %T, not the block", resp.Data)
	}
	return *data
}

func latchedData(t *testing.T, resp proto.BaseResponse) proto.ChatStateRekeyLatchedData {
	t.Helper()
	if resp.Success || string(resp.ErrorCode) != string(errs.ErrCodeChatStateRekeyRequired) {
		t.Fatalf("response = %+v; want %s", resp, string(errs.ErrCodeChatStateRekeyRequired))
	}
	data, ok := resp.Data.(proto.ChatStateRekeyLatchedData)
	if !ok {
		t.Fatalf("latch response carries %T, not the latch detail", resp.Data)
	}
	return data
}

// A plain member cannot build a Remove by claiming the app asked for it.
// Receipt-side attacks are exercised with a permissive MLS client in
// mls_adversary_e2e_cgo_test.go.
func TestMLSAuthority_APlainMemberCannotBuildARemoveOfAnotherMember(t *testing.T) {
	r := newRoom(t)
	assertCode(t, r.bob.call(proto.MLSCommitBuild, proto.MLSCommitBuildRequest{
		Permit: r.bob.permit(), OrgID: e2eOrg, ConversationID: e2eConv,
		ClientCommitID: r.bob.nextCommitID(), ExpectedEpoch: 2,
		RemoveAccountIDs: []string{e2eCarol}, UserInitiated: true,
	}), string(errs.ErrCodeChatMLSCommitUnauthorized))
}

// N3: a blocked row is not a dead end. Another, valid Commit for the same
// epoch (here Alice's own key update, accepted by the server once the bad row
// is gone) is applied and clears the block, and sends work again. The block
// never moved the confirmed state: the valid Commit applies to the epoch the
// refused one was built on.
func TestMLSAuthority_AValidCommitForTheBlockedEpochClearsTheBlock(t *testing.T) {
	r := newAdvRoom(t, false)
	lawfulSeq, lawfulB64 := r.lawfulRow()
	bad, _ := r.adv.Build(mlsadversary.Commit{Removes: []uint32{r.adv.IndexOf(e2eCarol, r.carol.device)}})
	badSeq := r.nextSeq()
	badReq := r.alice.processRequest(badSeq, 3, advB64(bad))
	badReq.CommitAttestation = attested(e2eAlice, e2eCarol, advMallory)
	blockedData(t, r.alice.call(proto.MLSProcess, badReq))
	good := commitOf(r.alice.must(proto.MLSCommitBuild, proto.MLSCommitBuildRequest{
		Permit: r.alice.permit(), OrgID: e2eOrg, ConversationID: e2eConv,
		ClientCommitID: r.alice.nextCommitID(), ExpectedEpoch: 2, UpdateSelf: true,
	}))
	r.alice.confirm(good.ClientCommitID, proto.MLSCommitOutcomeAccepted, "")
	lawful := r.carol.processRequest(lawfulSeq, 2, lawfulB64)
	if got := r.carol.must(proto.MLSProcess, lawful).Data.(proto.MLSProcessResponseData); got.Epoch != 2 {
		t.Fatalf("carol caught up on the lawful row at %+v", got)
	}
	if st := r.alice.status(); st.SyncBlocked != nil || st.NeedsRekey || st.Epoch != 3 {
		t.Fatalf("status after the valid commit = %+v", st)
	}
	r.alice.must(proto.MLSEncrypt, r.alice.encryptRequest(messageID(1), 3, "back in step"))
}

// The room's owner may request membership changes. Other members cannot gain
// that authority from user_initiated; signed statements still let any member
// carry an authorized removal.
func TestMLSAuthority_AutomationCannotBuildARemoveOrAnAdd(t *testing.T) {
	r := newRoom(t)
	resp := r.bob.buildRemove(2, e2eCarol)
	if resp.Success || string(resp.ErrorCode) != string(errs.ErrCodeChatMLSCommitUnauthorized) {
		t.Fatalf("an automated remove of another member = %+v", resp)
	}
	dave := newKeeper(t, "d4444444-4444-4444-8444-444444444444")
	add := r.bob.call(proto.MLSCommitBuild, proto.MLSCommitBuildRequest{
		Permit: r.bob.permit(), OrgID: e2eOrg, ConversationID: e2eConv,
		ClientCommitID: r.bob.nextCommitID(), ExpectedEpoch: 2,
		Add: []proto.MLSMemberKeyPackage{dave.keyPackage()},
	})
	if add.Success || string(add.ErrorCode) != string(errs.ErrCodeChatMLSCommitUnauthorized) {
		t.Fatalf("an automated add = %+v", add)
	}
	if got := r.bob.status(); got.CommitPending {
		t.Fatal("a refused build left a pending Commit")
	}
	r.bob.refused(proto.MLSCommitBuild, proto.MLSCommitBuildRequest{
		Permit: r.bob.permit(), OrgID: e2eOrg, ConversationID: e2eConv,
		ClientCommitID: r.bob.nextCommitID(), ExpectedEpoch: 2, UpdateSelf: true, UserInitiated: true,
	}, string(errs.ErrCodeChatStateInvalidInput))

	// The permit naming a departure is no longer enough (wave 5a): only the
	// org admin's signed statement makes it anyone's to carry out.
	r.bob.refused(proto.MLSCommitBuild, proto.MLSCommitBuildRequest{
		Permit: r.bob.permit(e2eCarol), OrgID: e2eOrg, ConversationID: e2eConv,
		ClientCommitID: r.bob.nextCommitID(), ExpectedEpoch: 2, RemoveAccountIDs: []string{e2eCarol},
	}, string(errs.ErrCodeChatMLSCommitUnauthorized))
	r.bob.must(proto.MLSCommitBuild, proto.MLSCommitBuildRequest{
		Permit: r.bob.permit(e2eCarol), OrgID: e2eOrg, ConversationID: e2eConv,
		ClientCommitID: r.bob.nextCommitID(), ExpectedEpoch: 2, RemoveAccountIDs: []string{e2eCarol},
		OrgRemovalStatements: []proto.MLSOrgRemovalStatement{orgRemoval(newKeeper(t, e2eAdmin), e2eCarol)},
	})
}

// The room's owner may remove members. Any member may also carry an
// org-admin-signed removal statement, independent of the server's roster.
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
		string(errs.ErrCodeChatMLSRotationPending))
	// Now the server has cleared the row and serves no attestation (an old
	// row): the statement inside the Commit is what carol verifies.
	if got := r2.carol.process(r2.nextSeq(), 3, departed.CommitB64); got.Epoch != 3 {
		t.Fatalf("carol applied the departure at %+v", got)
	}
}

// A received Add by the room's owner stands on the group's roles and its
// leaf and trust checks. Neither the row's attestation nor its absence is
// authority for it, so a server that signs a member set without the account
// changes nothing.
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
		string(errs.ErrCodeChatMLSEpochStale))

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
	c.bob.refused(proto.MLSProcess, req, string(errs.ErrCodeChatStateNotAuthorized))
	if got := c.bob.status(); got.NeedsRekey || got.Epoch != 1 {
		t.Fatalf("a refused attestation moved the state: %+v", got)
	}
}

// Q20: a Commit that lost its epoch reports what the winner did, so the app
// can stop when the winner touched the accounts it was about.
func TestMLSAuthority_ALostRaceReportsWhatTheWinnerDid(t *testing.T) {
	r := newRoom(t)
	winner := commitOf(r.bob.must(proto.MLSCommitBuild, proto.MLSCommitBuildRequest{
		Permit: r.bob.permit(e2eCarol), OrgID: e2eOrg, ConversationID: e2eConv,
		ClientCommitID: r.bob.nextCommitID(), ExpectedEpoch: 2, RemoveAccountIDs: []string{e2eCarol},
		OrgRemovalStatements: []proto.MLSOrgRemovalStatement{orgRemoval(newKeeper(t, e2eAdmin), e2eCarol)},
	}))
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
	r2 := newAdvRoom(t, false)
	lawfulSeq, lawfulB64 := r2.lawfulRow()
	lost := r2.alice.buildUpdate(2)
	bad, _ := r2.adv.Build(mlsadversary.Commit{Removes: []uint32{r2.adv.IndexOf(e2eCarol, r2.carol.device)}})
	blockedData(t, r2.alice.call(proto.MLSCommitConfirm, proto.MLSCommitConfirmRequest{
		Permit: r2.alice.permit(), OrgID: e2eOrg, ConversationID: e2eConv,
		ClientCommitID: lost.ClientCommitID, Outcome: proto.MLSCommitOutcomeSuperseded,
		WinnerCommitB64: advB64(bad), WinnerAttestation: attested(e2eAlice, e2eCarol, advMallory),
	}))
	if st := r2.alice.status(); st.CommitPending || st.SyncBlocked == nil || st.Epoch != 2 {
		t.Fatalf("status after the unauthorized winner = %+v", st)
	}
	lawful := r2.carol.processRequest(lawfulSeq, 2, lawfulB64)
	if got := r2.carol.must(proto.MLSProcess, lawful).Data.(proto.MLSProcessResponseData); got.Epoch != 2 {
		t.Fatalf("carol caught up on the lawful row at %+v", got)
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
