//go:build mls && cgo

// The validity window of an org removal and a leave (Q10): a statement signed
// more than MLSStatementMaxAgeSeconds before this Keeper's clock is refused,
// at build here and on receipt (mls_adversary_e2e_cgo_test.go). That bounds
// how long a server can re-serve an old statement against an account that
// came back.

package dispatch

import (
	"testing"
	"time"

	"github.com/dragpass/keeper/internal/keystore/proto"
)

// signedAgo makes k sign as if its clock read age ago.
func (k *keeper) signedAgo(age time.Duration, sign func() any) any {
	k.t.Helper()
	k.deps.Clock = func() time.Time { return time.Now().Add(-age) }
	defer func() { k.deps.Clock = nil }()
	return sign()
}

const day = 24 * time.Hour

// leaveAgo is k's signed leave as if its clock read age ago, under a permit
// the server issued at that time.
func (k *keeper) leaveAgo(age time.Duration) proto.MLSLeaveStatement {
	k.t.Helper()
	permit := k.permit()
	permit.IssuedAt -= int64(age / time.Second)
	permit.ExpiresAt -= int64(age / time.Second)
	return k.signedAgo(age, func() any {
		return k.must(proto.MLSLeaveRequestSign, proto.MLSLeaveRequestSignRequest{
			Permit: permit, OrgID: e2eOrg, ConversationID: e2eConv,
		}).Data.(proto.MLSLeaveRequestSignResponseData).Statement
	}).(proto.MLSLeaveStatement)
}

func TestMLSStatementWindow_AnOrgRemovalOlderThanThirtyDaysIsRefusedAtBuild(t *testing.T) {
	r := newRolesRoom(t)
	admin := newKeeper(t, e2eAdmin)
	old := admin.signedAgo(31*day, func() any { return orgRemoval(admin, e2eCarol) }).(proto.MLSOrgRemovalStatement)

	req := r.bob.buildRequest(1)
	req.Permit, req.RemoveAccountIDs = r.bob.permit(e2eCarol), []string{e2eCarol}
	req.OrgRemovalStatements = []proto.MLSOrgRemovalStatement{old}
	assertCode(t, r.bob.call(proto.MLSCommitBuild, req), proto.ChatMLSErrorCodeStatementUnverified)
	if got := r.bob.status(); got.CommitPending || got.Epoch != 1 {
		t.Fatalf("a refused build left %+v", got)
	}

	// Inside the window the same statement shape is carried out.
	recent := admin.signedAgo(29*day, func() any { return orgRemoval(admin, e2eCarol) }).(proto.MLSOrgRemovalStatement)
	req.ClientCommitID, req.OrgRemovalStatements = r.bob.nextCommitID(), []proto.MLSOrgRemovalStatement{recent}
	removed := r.bob.accepted(req)
	if got := r.alice.process(r.nextSeq(), 2, removed.CommitB64); got.Epoch != 2 {
		t.Fatalf("alice applied the recent removal at %+v", got)
	}
}

func TestMLSStatementWindow_ALeaveOlderThanThirtyDaysIsRefusedAtBuild(t *testing.T) {
	r := newRolesRoom(t)
	old := r.carol.leaveAgo(31 * day)

	req := r.bob.buildRequest(1)
	req.RemoveAccountIDs, req.LeaveStatements = []string{e2eCarol}, []proto.MLSLeaveStatement{old}
	assertCode(t, r.bob.call(proto.MLSCommitBuild, req), proto.ChatMLSErrorCodeStatementUnverified)

	recent := r.carol.leaveAgo(29 * day)
	req.ClientCommitID, req.LeaveStatements = r.bob.nextCommitID(), []proto.MLSLeaveStatement{recent}
	removed := r.bob.accepted(req)
	if got := r.alice.process(r.nextSeq(), 2, removed.CommitB64); got.Epoch != 2 {
		t.Fatalf("alice applied the recent leave at %+v", got)
	}
}

// On receipt the window is read against the receiver's own clock. A Commit
// built on a 29-day-old statement is applied by a member whose clock agrees,
// and refused (blocked at that epoch, unauthorized_commit, naming the committer) by one whose
// clock is three days later: the case of a device that catches up after being
// away. The receiver has no trusted time for when the Commit was accepted,
// which is the stated cost of the window.
func TestMLSStatementWindow_AReceiverPastTheWindowRefusesTheRemove(t *testing.T) {
	r := newRolesRoom(t)
	admin := newKeeper(t, e2eAdmin)
	statement := admin.signedAgo(29*day, func() any { return orgRemoval(admin, e2eCarol) }).(proto.MLSOrgRemovalStatement)
	req := r.bob.buildRequest(1)
	req.Permit, req.RemoveAccountIDs = r.bob.permit(e2eCarol), []string{e2eCarol}
	req.OrgRemovalStatements = []proto.MLSOrgRemovalStatement{statement}
	removed := r.bob.accepted(req)

	r.alice.deps.Clock = func() time.Time { return time.Now().Add(3 * day) }
	defer func() { r.alice.deps.Clock = nil }()
	seq := r.nextSeq()
	resp := r.alice.call(proto.MLSProcess, r.alice.processRequestAt(seq, 2, removed.CommitB64, 3*day))
	got := blockedData(t, resp)
	if got.Cause != proto.ChatStateRekeyCauseUnauthorizedCommit || got.CommitterAccountID != e2eBob {
		t.Fatalf("latch detail = %+v", got)
	}
}

// processRequestAt is processRequest under a permit issued ahead by skew, for
// a Keeper whose clock reads that much later.
func (k *keeper) processRequestAt(seq, epoch uint64, commitB64 string, skew time.Duration) proto.MLSProcessRequest {
	req := k.processRequest(seq, epoch, commitB64)
	req.Permit.IssuedAt += int64(skew / time.Second)
	req.Permit.ExpiresAt += int64(skew / time.Second)
	return req
}
