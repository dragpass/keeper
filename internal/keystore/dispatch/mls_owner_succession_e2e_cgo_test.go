//go:build mls && cgo

// Owner succession (N6). The rule the user approved, verbatim: "방장 leaf 가
// 빠진 방은 관리자, 관리자가 없으면 아무 멤버가 방장 자리를 가져갈 수 있다. 서버의
// 승계 순서(관리자 먼저, 그다음 오래된 멤버)와 맞춰 두었다." The Keeper decides it
// from the authenticated group state alone (roles::is_ownerless_claim): the
// owner's leaf must be gone, removed on verified evidence (here an org admin's
// signed removal statement), and whom the server nominates is never read.

package dispatch

import (
	"testing"

	"github.com/dragpass/keeper/internal/keystore/proto"
)

// ownerRemoved is a room with Alice as owner and admins as given, after Bob
// carried out Alice's signed org removal at epoch 2, applied by Carol.
func ownerRemoved(t *testing.T, admins ...string) *room {
	t.Helper()
	r := newRolesRoom(t, admins...)
	admin := newKeeper(t, e2eAdmin)
	req := r.bob.buildRequest(1)
	req.Permit, req.RemoveAccountIDs = r.bob.permit(e2eAlice), []string{e2eAlice}
	req.OrgRemovalStatements = []proto.MLSOrgRemovalStatement{orgRemoval(admin, e2eAlice)}
	removed := r.bob.accepted(req)
	if got := r.carol.process(r.nextSeq(), 2, removed.CommitB64); got.Epoch != 2 {
		t.Fatalf("carol applied the owner's removal at %+v", got)
	}
	return r
}

func ownerOf(t *testing.T, k *keeper) string {
	t.Helper()
	for _, e := range k.status().Roles {
		if e.Role == proto.MLSRoleOwner {
			return e.AccountID
		}
	}
	return ""
}

// The server nominates Carol, a plain member, while Bob, an admin, holds a
// leaf. The Keeper does not read the nomination: Carol's claim is refused
// before anything is built, and Bob's is built and applied by Carol.
func TestMLSOwnerSuccession_TheServersNomineeIsNotTheRule(t *testing.T) {
	r := ownerRemoved(t, e2eBob)
	claim := r.carol.buildRequest(2)
	claim.SetRoles = roleSet(e2eCarol, e2eBob)
	assertCode(t, r.carol.call(proto.MLSCommitBuild, claim), proto.ChatMLSErrorCodeCommitUnauthorized)
	claim.ClientCommitID, claim.SetRoles = r.carol.nextCommitID(), roleSet(e2eCarol)
	assertCode(t, r.carol.call(proto.MLSCommitBuild, claim), proto.ChatMLSErrorCodeCommitUnauthorized)
	if got := r.carol.status(); got.CommitPending || got.Epoch != 2 {
		t.Fatalf("a refused claim left %+v", got)
	}

	bob := r.bob.buildRequest(2)
	bob.SetRoles = roleSet(e2eBob)
	claimed := r.bob.accepted(bob)
	if got := r.carol.process(r.nextSeq(), 3, claimed.CommitB64); got.Epoch != 3 {
		t.Fatalf("carol applied the admin's claim at %+v", got)
	}
	if got := ownerOf(t, r.carol); got != e2eBob {
		t.Fatalf("owner after the claim = %s", got)
	}
}

// No admin: any member may claim, and two claim at once. The server accepts
// one (its CAS decides the epoch); the other's pending claim loses the epoch
// and the winner's claim is applied in its place, so both end with the same
// owner. Nobody else's power changed.
func TestMLSOwnerSuccession_TwoMembersClaimAtOnce(t *testing.T) {
	r := ownerRemoved(t)
	bobReq := r.bob.buildRequest(2)
	bobReq.SetRoles = roleSet(e2eBob)
	bobClaim := commitOf(r.bob.must(proto.MLSCommitBuild, bobReq))
	carolReq := r.carol.buildRequest(2)
	carolReq.SetRoles = roleSet(e2eCarol)
	carolClaim := commitOf(r.carol.must(proto.MLSCommitBuild, carolReq))

	r.bob.confirm(bobClaim.ClientCommitID, proto.MLSCommitOutcomeAccepted, "")
	got := r.carol.must(proto.MLSCommitConfirm, proto.MLSCommitConfirmRequest{
		Permit: r.carol.permit(), OrgID: e2eOrg, ConversationID: e2eConv,
		ClientCommitID: carolClaim.ClientCommitID, Outcome: proto.MLSCommitOutcomeSuperseded,
		WinnerCommitB64: bobClaim.CommitB64,
	}).Data.(proto.MLSCommitConfirmResponseData)
	if got.Epoch != 3 {
		t.Fatalf("carol's lost claim settled at %+v", got)
	}
	for _, k := range []*keeper{r.bob, r.carol} {
		if owner := ownerOf(t, k); owner != e2eBob {
			t.Fatalf("%s sees owner %s", k.id[:8], owner)
		}
	}
	// Carol cannot now take it back: Bob holds a leaf.
	again := r.carol.buildRequest(3)
	again.SetRoles = roleSet(e2eCarol)
	assertCode(t, r.carol.call(proto.MLSCommitBuild, again), proto.ChatMLSErrorCodeCommitUnauthorized)
}

// A claim needs the owner's leaf to be gone: while Alice still holds one, no
// admin or member may take the room, whatever the server says about her.
func TestMLSOwnerSuccession_NoClaimWhileTheOwnerHoldsALeaf(t *testing.T) {
	r := newRolesRoom(t, e2eBob)
	claim := r.bob.buildRequest(1)
	claim.SetRoles = roleSet(e2eBob)
	assertCode(t, r.bob.call(proto.MLSCommitBuild, claim), proto.ChatMLSErrorCodeCommitUnauthorized)
}

// P1-1: the owner Alice and the only admin Bob are both removed from the
// organization, on the admin's signed statements, and only Carol and Dave
// remain. Carol claims the room; her claim drops Bob's departed entry, and
// Dave applies it.
func TestMLSOwnerSuccession_TheOwnerAndTheOnlyAdminLeft(t *testing.T) {
	r := newRolesRoom(t, e2eBob)
	dave := newKeeper(t, e2eDave)
	add := r.alice.buildRequest(1)
	add.Add, add.UserInitiated = []proto.MLSMemberKeyPackage{dave.keyPackage()}, true
	added := r.alice.accepted(add)
	for _, k := range []*keeper{r.bob, r.carol} {
		k.process(r.nextSeq(), 2, added.CommitB64)
	}
	dave.must(proto.MLSJoin, proto.MLSJoinRequest{Permit: dave.permit(), OrgID: e2eOrg, ConversationID: e2eConv, WelcomeB64: added.WelcomeB64})

	orgAdmin := newKeeper(t, e2eAdmin)
	req := r.carol.buildRequest(2)
	req.Permit, req.RemoveAccountIDs = r.carol.permit(e2eAlice, e2eBob), []string{e2eAlice, e2eBob}
	req.OrgRemovalStatements = []proto.MLSOrgRemovalStatement{orgRemoval(orgAdmin, e2eAlice), orgRemoval(orgAdmin, e2eBob)}
	removed := r.carol.accepted(req)
	if got := dave.process(r.nextSeq(), 3, removed.CommitB64); got.Epoch != 3 {
		t.Fatalf("dave applied the removals at %+v", got)
	}

	claim := r.carol.buildRequest(3)
	claim.SetRoles = roleSet(e2eCarol)
	claimed := r.carol.accepted(claim)
	if got := dave.process(r.nextSeq(), 4, claimed.CommitB64); got.Epoch != 4 {
		t.Fatalf("dave applied carol's claim at %+v", got)
	}
	if got := ownerOf(t, dave); got != e2eCarol {
		t.Fatalf("owner after the claim = %s", got)
	}
	if got := dave.status().Roles; len(got) != 1 {
		t.Fatalf("roles after the claim = %+v; want carol alone", got)
	}
}
