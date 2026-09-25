//go:build mls && cgo

// A group that mixes a Keeper from before wave 5 (main 4134f9f) with this
// one (wave 5c item 12). Each device runs its own binary over Native
// Messaging; the old one is given permits of canonical version 4, as the old
// server would sign them.
//
// The old binary is not in this repository: build it from 4134f9f with
// `-tags mls` and name it in KEEPER_KILLHARNESS_OLD_BINARY. Without it these
// tests are skipped, which CI does; the run and its result are recorded in
// the wave 5 PR.

package killharness

import (
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/proto"
)

const oldBinaryEnv = "KEEPER_KILLHARNESS_OLD_BINARY"

func oldBinary(t *testing.T) string {
	t.Helper()
	bin := os.Getenv(oldBinaryEnv)
	if bin == "" {
		t.Skip(oldBinaryEnv + " names no Keeper build from before wave 5")
	}
	return bin
}

// permitV4Canonical is the canonical version 4 permit: version 5's without
// the pending_device_revocations slot.
func permitV4Canonical(p proto.ChatStatePermit) string {
	parts := []string{proto.ChatStatePermitDomain, "4", p.AccountID, p.OrgID, p.ConversationID,
		strconv.FormatUint(p.WatermarkEpoch, 10), strconv.FormatUint(uint64(p.WatermarkLeafIndex), 10),
		strconv.FormatUint(p.WatermarkNextHandshake, 10), strconv.FormatUint(p.WatermarkNextApplication, 10),
		strings.Join(p.PendingRemovalAccountIDs, ",")}
	var repl []string
	for _, r := range p.PendingLeafReplacements {
		repl = append(repl, r.AccountID+":"+r.NewSignatureKeyFP)
	}
	parts = append(parts, strings.Join(repl, ","), strconv.FormatInt(p.IssuedAt, 10),
		strconv.FormatInt(p.ExpiresAt, 10), strconv.FormatUint(uint64(p.ServerKeyVersion), 10))
	return strings.Join(parts, "|")
}

// withV4Permit rewrites a request's permit as the old server would send it.
func (d *device) withV4Permit(payload any) any {
	d.t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		d.t.Fatal(err)
	}
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil || m["permit"] == nil {
		return payload
	}
	var p proto.ChatStatePermit
	pr, _ := json.Marshal(m["permit"])
	if err := json.Unmarshal(pr, &p); err != nil {
		d.t.Fatal(err)
	}
	v4 := map[string]any{}
	if err := json.Unmarshal(pr, &v4); err != nil {
		d.t.Fatal(err)
	}
	delete(v4, "pending_device_revocations")
	v4["signature"] = sign(d.t, permitV4Canonical(p))
	m["permit"] = v4
	return m
}

func newOldDevice(t *testing.T, account string) *device {
	d := newDevice(t, account)
	d.binary, d.v4Permit = oldBinary(t), true
	return d
}

type mixed struct {
	alice, carol *device // this Keeper
	bob          *device // the old one
	a, c, b      *keeperProc
	seq          uint64
}

func (m *mixed) nextSeq() uint64 {
	m.seq++
	return m.seq
}

// newMixedRoom is a room without roles (the old Keeper cannot hold them)
// that new Alice creates with old Bob and new Carol, all at epoch 1.
func newMixedRoom(t *testing.T) *mixed {
	t.Helper()
	m := &mixed{alice: newDevice(t, hAlice), bob: newOldDevice(t, hBob), carol: newDevice(t, hCarol), seq: 1}
	m.a, m.b, m.c = m.alice.start("", 0), m.bob.start("", 0), m.carol.start("", 0)
	m.a.enrol()
	m.b.enrol()
	m.c.enrol()
	id := m.alice.nextCommitID()
	var built proto.MLSCommitResponseData
	m.a.must(proto.MLSGroupCreate, proto.MLSGroupCreateRequest{
		Permit: m.alice.permit(), OrgID: hOrg, ConversationID: hConv, ClientCommitID: id,
		Members: []proto.MLSMemberKeyPackage{m.b.keyPackage(), m.c.keyPackage()},
	}, &built)
	m.a.must(proto.MLSCommitConfirm, m.alice.confirmRequest(id), nil)
	for _, p := range []*keeperProc{m.b, m.c} {
		p.must(proto.MLSJoin, proto.MLSJoinRequest{
			Permit: p.d.permit(), OrgID: hOrg, ConversationID: hConv, WelcomeB64: built.WelcomeB64,
		}, nil)
	}
	return m
}

// Messages cross both ways in a room without roles, and a key update by the
// old Keeper is applied by the new ones and the other way round.
func TestMixedVersion_ALegacyRoomWorksAcrossVersions(t *testing.T) {
	m := newMixedRoom(t)
	fromOld := m.b.encrypt(messageID(1), 1, "from the old keeper")
	got := m.a.decrypt(proto.MLSDisplayMessage{Seq: m.nextSeq(), CiphertextB64: fromOld.CiphertextB64})
	if text(t, got.PlaintextB64[0]) != "from the old keeper" {
		t.Fatalf("alice read %+v", got)
	}
	fromNew := m.a.encrypt(messageID(2), 1, "from the new keeper")
	got = m.b.decrypt(proto.MLSDisplayMessage{Seq: m.nextSeq(), CiphertextB64: fromNew.CiphertextB64})
	if text(t, got.PlaintextB64[0]) != "from the new keeper" {
		t.Fatalf("old bob read %+v", got)
	}

	update := m.b.buildUpdate(m.bob.nextCommitID(), 1)
	m.b.must(proto.MLSCommitConfirm, m.bob.confirmRequest(update.ClientCommitID), nil)
	seq := m.nextSeq()
	for _, p := range []*keeperProc{m.a, m.c} {
		var out proto.MLSProcessResponseData
		p.must(proto.MLSProcess, p.d.attestedProcess(seq, 2, update.CommitB64, hAlice, hBob, hCarol), &out)
		if out.Epoch != 2 {
			t.Fatalf("%s applied the old keeper's update at %+v", p.d.account[:8], out)
		}
	}
	back := m.a.buildUpdate(m.alice.nextCommitID(), 2)
	m.a.must(proto.MLSCommitConfirm, m.alice.confirmRequest(back.ClientCommitID), nil)
	var out proto.MLSProcessResponseData
	m.b.must(proto.MLSProcess, m.bob.attestedProcess(m.nextSeq(), 3, back.CommitB64, hAlice, hBob, hCarol), &out)
	if out.Epoch != 3 {
		t.Fatalf("old bob applied the new keeper's update at %+v", out)
	}
}

// The new Keeper cannot give such a room roles, or create a room with roles
// for the old Keeper's KeyPackage: its leaf does not advertise 0xF0D1. Both
// refuse clearly and build nothing.
func TestMixedVersion_RolesNeedEveryLeafToSupportThem(t *testing.T) {
	m := newMixedRoom(t)
	if st := m.a.status(); st.Authority != "legacy_temporary" || st.RolesMigratable {
		t.Fatalf("alice's view of the mixed room = %+v", st)
	}
	m.a.refused(proto.MLSCommitBuild, proto.MLSCommitBuildRequest{
		Permit: m.alice.permit(), OrgID: hOrg, ConversationID: hConv, ClientCommitID: m.alice.nextCommitID(),
		ExpectedEpoch: 1, UserInitiated: true,
		SetRoles: &proto.MLSRoleSet{Kind: proto.MLSRolesKindRoom, Entries: []proto.MLSRoleEntry{{AccountID: hAlice, Role: proto.MLSRoleOwner}}},
	}, proto.ChatMLSErrorCodeRolesUnsupported)

	other := newDevice(t, "d4444444-4444-4444-8444-444444444444")
	o := other.start("", 0)
	o.enrol()
	o.refused(proto.MLSGroupCreate, proto.MLSGroupCreateRequest{
		Permit: other.permitFor("cccccccc-cccc-4ccc-8ccc-cccccccccccc"), OrgID: hOrg,
		ConversationID: "cccccccc-cccc-4ccc-8ccc-cccccccccccc", ClientCommitID: other.nextCommitID(),
		Members: []proto.MLSMemberKeyPackage{m.b.keyPackage()},
		Roles:   &proto.MLSRoleSet{Kind: proto.MLSRolesKindRoom, Entries: []proto.MLSRoleEntry{{AccountID: other.account, Role: proto.MLSRoleOwner}}},
	}, proto.ChatMLSErrorCodeRolesUnsupported)
}

// The old Keeper removes Carol with nothing the new rules accept (a
// same-set Remove its user_initiated flag let through). New Alice refuses it
// and stops at that epoch; she is not latched.
func TestMixedVersion_AnOldKeepersUnauthorizedRemoveBlocksTheNewOne(t *testing.T) {
	m := newMixedRoom(t)
	var built proto.MLSCommitResponseData
	m.b.must(proto.MLSCommitBuild, proto.MLSCommitBuildRequest{
		Permit: m.bob.permit(), OrgID: hOrg, ConversationID: hConv, ClientCommitID: m.bob.nextCommitID(),
		ExpectedEpoch: 1, RemoveAccountIDs: []string{hCarol}, UserInitiated: true,
	}, &built)
	m.b.must(proto.MLSCommitConfirm, m.bob.confirmRequest(built.ClientCommitID), nil)
	got := blockDetail(t, m.a.call(proto.MLSProcess, m.alice.attestedProcess(m.nextSeq(), 2, built.CommitB64, hAlice, hBob, hCarol)))
	if got.Cause != proto.ChatStateRekeyCauseUnauthorizedCommit || got.CommitterAccountID != hBob {
		t.Fatalf("alice's block = %+v", got)
	}
	if st := m.a.status(); st.NeedsRekey || st.SyncBlocked == nil {
		t.Fatalf("alice's status = %+v", st)
	}
}

// A signed leave the new Keeper carries out, received by the old Keeper: the
// old Keeper does not read the statement in the Commit's authenticated data,
// and judges the Remove by its own wave 4 rules (here the server's signed
// member set, R3b).
func TestMixedVersion_ANewKeepersSignedLeaveIsAppliedByTheOldOne(t *testing.T) {
	m := newMixedRoom(t)
	var leave proto.MLSLeaveRequestSignResponseData
	m.c.must(proto.MLSLeaveRequestSign, proto.MLSLeaveRequestSignRequest{
		Permit: m.carol.permit(), OrgID: hOrg, ConversationID: hConv,
	}, &leave)
	var built proto.MLSCommitResponseData
	m.a.must(proto.MLSCommitBuild, proto.MLSCommitBuildRequest{
		Permit: m.alice.permit(), OrgID: hOrg, ConversationID: hConv, ClientCommitID: m.alice.nextCommitID(),
		ExpectedEpoch: 1, RemoveAccountIDs: []string{hCarol},
		LeaveStatements: []proto.MLSLeaveStatement{leave.Statement},
	}, &built)
	m.a.must(proto.MLSCommitConfirm, m.alice.confirmRequest(built.ClientCommitID), nil)
	r := m.b.call(proto.MLSProcess, m.bob.attestedProcess(m.nextSeq(), 2, built.CommitB64, hAlice, hBob))
	t.Logf("old keeper on the signed leave: success=%t code=%s", r.Success, r.ErrorCode)
	if !r.Success {
		t.Fatalf("the old keeper refused a lawful leave: %+v", r)
	}
}

// permitFor is permit for another conversation.
func (d *device) permitFor(conversationID string) proto.ChatStatePermit {
	p := d.permit()
	p.ConversationID = conversationID
	p.Signature = sign(d.t, proto.ChatStatePermitCanonical(p))
	return p
}
