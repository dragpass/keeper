//go:build mls && cgo

// Wave 5a in the Keeper binary: a room whose roles are in the group context,
// a signed leave carried out under contention between two processes of one
// device, a refused roles change that writes nothing across a SIGKILL, and
// the device revocation latch surviving one. Every permit is signed by the
// test server key the Keeper's own verifier checks.

package killharness

import (
	"encoding/json"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/proto"
)

// newRolesThreeParty is newThreeParty with Alice setting the room's roles at
// create: Alice owner, nobody else listed.
func newRolesThreeParty(t *testing.T) *threeParty {
	t.Helper()
	alice, bob, carol := newDevice(t, hAlice), newDevice(t, hBob), newDevice(t, hCarol)
	a, b, c := alice.start("", 0), bob.start("", 0), carol.start("", 0)
	a.enrol()
	b.enrol()
	c.enrol()
	id := alice.nextCommitID()
	var built proto.MLSCommitResponseData
	a.must(proto.MLSGroupCreate, proto.MLSGroupCreateRequest{
		Permit: alice.permit(), OrgID: hOrg, ConversationID: hConv, ClientCommitID: id,
		Members: []proto.MLSMemberKeyPackage{b.keyPackage(), c.keyPackage()},
		Roles: &proto.MLSRoleSet{Kind: proto.MLSRolesKindRoom,
			Entries: []proto.MLSRoleEntry{{AccountID: hAlice, Role: proto.MLSRoleOwner}}},
	}, &built)
	a.must(proto.MLSCommitConfirm, alice.confirmRequest(id), nil)
	for _, p := range []*keeperProc{b, c} {
		p.must(proto.MLSJoin, proto.MLSJoinRequest{
			Permit: p.d.permit(), OrgID: hOrg, ConversationID: hConv, WelcomeB64: built.WelcomeB64,
		}, nil)
	}
	for _, p := range []*keeperProc{a, b, c} {
		p.in.Close()
		<-p.done
	}
	return &threeParty{alice: alice, bob: bob, carol: carol, seq: 1}
}

func (d *device) permitRevoking(refs ...proto.MLSDeviceRef) proto.ChatStatePermit {
	p := d.permit()
	p.PendingDeviceRevocations = refs
	p.Signature = sign(d.t, proto.ChatStatePermitCanonical(p))
	return p
}

// Two Keeper processes of Bob's device race to carry out Carol's signed
// leave. One builds the Remove and the other is told a Commit is already
// pending, never a second fork; the builder dies before the verdict, the
// restarted one confirms the same bytes, and Alice applies them from the
// statement inside the Commit.
func TestKeeperProcessesContendOverASignedLeave(t *testing.T) {
	g := newRolesThreeParty(t)
	c := g.carol.start("", 0)
	var signed proto.MLSLeaveRequestSignResponseData
	c.must(proto.MLSLeaveRequestSign, proto.MLSLeaveRequestSignRequest{
		Permit: g.carol.permit(), OrgID: hOrg, ConversationID: hConv,
	}, &signed)
	c.in.Close()
	<-c.done

	request := func() proto.MLSCommitBuildRequest {
		return proto.MLSCommitBuildRequest{
			Permit: g.bob.permit(), OrgID: hOrg, ConversationID: hConv,
			ClientCommitID: g.bob.nextCommitID(), ExpectedEpoch: 1, RemoveAccountIDs: []string{hCarol},
			LeaveStatements: []proto.MLSLeaveStatement{signed.Statement},
		}
	}
	p1, p2 := g.bob.start("", 0), g.bob.start("", 0)
	r1, r2 := request(), request()
	p1.send(proto.MLSCommitBuild, r1)
	p2.send(proto.MLSCommitBuild, r2)
	var built proto.MLSCommitResponseData
	winners := 0
	for _, p := range []*keeperProc{p1, p2} {
		r, err := p.receive()
		if err != nil {
			t.Fatalf("no answer: %v\n%s", err, p.stderr.String())
		}
		switch {
		case r.Success:
			winners++
			if err := json.Unmarshal(r.Data, &built); err != nil {
				t.Fatal(err)
			}
		case r.ErrorCode != proto.ChatMLSErrorCodeCommitPending:
			t.Fatalf("the loser answered %+v", r)
		}
	}
	if winners != 1 {
		t.Fatalf("%d processes built the leave; want exactly one", winners)
	}
	p1.killAndAssertKilled()
	p2.killAndAssertKilled()

	b := g.bob.start("", 0)
	if status := b.status(); !status.CommitPending || status.PendingClientCommitID != built.ClientCommitID {
		t.Fatalf("bob's status after the kill = %+v", status)
	}
	b.must(proto.MLSCommitConfirm, g.bob.confirmRequest(built.ClientCommitID), nil)

	a := g.alice.start("", 0)
	var processed proto.MLSProcessResponseData
	a.must(proto.MLSProcess, g.alice.processRequest(g.nextSeq(), 2, built.CommitB64), &processed)
	if processed.Epoch != 2 {
		t.Fatalf("alice applied the leave at %+v", processed)
	}
}

// Carol, a plain member, asks her Keeper for a roles change that makes her
// the owner. It is refused before anything is built; after a SIGKILL the
// record still has no pending Commit and the roles are Alice's.
func TestKeeperProcessRefusesAMembersRolesChangeAndWritesNothing(t *testing.T) {
	g := newRolesThreeParty(t)
	c := g.carol.start("", 0)
	c.refused(proto.MLSCommitBuild, proto.MLSCommitBuildRequest{
		Permit: g.carol.permit(), OrgID: hOrg, ConversationID: hConv,
		ClientCommitID: g.carol.nextCommitID(), ExpectedEpoch: 1, UserInitiated: true,
		SetRoles: &proto.MLSRoleSet{Kind: proto.MLSRolesKindRoom,
			Entries: []proto.MLSRoleEntry{{AccountID: hCarol, Role: proto.MLSRoleOwner}}},
	}, proto.ChatMLSErrorCodeCommitUnauthorized)
	c.killAndAssertKilled()

	c = g.carol.start("", 0)
	status := c.status()
	if status.CommitPending || status.Epoch != 1 || status.Authority != "roles" ||
		len(status.Roles) != 1 || status.Roles[0].AccountID != hAlice {
		t.Fatalf("carol's status after the kill = %+v", status)
	}
}

// The permit names Carol's revoked device. Alice's sends latch; a later permit
// that leaves it out, even after a SIGKILL, does not lift the latch. Bob
// removes the leaf on Carol's signed revocation, and Alice sends again.
func TestKeeperProcessHoldsTheDeviceRevocationLatchAcrossAKill(t *testing.T) {
	g := newRolesThreeParty(t)
	c := g.carol.start("", 0)
	var revoked proto.MLSDeviceRevokeSignResponseData
	c.must(proto.MLSDeviceRevokeSign, proto.MLSDeviceRevokeSignRequest{AccountID: hCarol, DeviceID: hDevice}, &revoked)
	c.in.Close()
	<-c.done
	ref := proto.MLSDeviceRef{AccountID: hCarol, DeviceID: hDevice}

	a := g.alice.start("", 0)
	req := g.alice.encryptRequest(messageID(1), 1, "to carol's old device")
	req.Permit = g.alice.permitRevoking(ref)
	a.refused(proto.MLSEncrypt, req, proto.ChatMLSErrorCodeRotationPending)
	a.killAndAssertKilled()

	a = g.alice.start("", 0)
	a.refused(proto.MLSEncrypt, g.alice.encryptRequest(messageID(1), 1, "the permit forgot"),
		proto.ChatMLSErrorCodeRotationPending)

	b := g.bob.start("", 0)
	var built proto.MLSCommitResponseData
	b.must(proto.MLSCommitBuild, proto.MLSCommitBuildRequest{
		Permit: g.bob.permitRevoking(ref), OrgID: hOrg, ConversationID: hConv,
		ClientCommitID: g.bob.nextCommitID(), ExpectedEpoch: 1,
		RevokeDevices: []proto.MLSDeviceRef{ref}, DeviceRevocations: []proto.MLSDeviceRevocation{revoked.Statement},
	}, &built)
	b.must(proto.MLSCommitConfirm, g.bob.confirmRequest(built.ClientCommitID), nil)
	a.must(proto.MLSProcess, g.alice.processRequest(g.nextSeq(), 2, built.CommitB64), nil)
	a.encrypt(messageID(1), 2, "the old device is out")
}
