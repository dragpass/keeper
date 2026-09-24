//go:build mls && cgo

// Wave 5a end to end (chatstate/authority.go, chatstate/roles.go): room roles
// in the group context, the admin-signed org removal, the signed leave and
// device revocation, and the legacy groups that carry no roles. Several
// Keepers in one process, and this test standing in for ariadne — including a
// server that omits, replays and tampers with what it serves.

package dispatch

import (
	"encoding/base64"
	"slices"
	"testing"
	"time"

	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

const (
	e2eDave  = "d4444444-4444-4444-8444-444444444444"
	e2eAdmin = "e5555555-5555-4555-8555-555555555555"
	e2eConv2 = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
)

func roleSet(owner string, admins ...string) *proto.MLSRoleSet {
	set := &proto.MLSRoleSet{Kind: proto.MLSRolesKindRoom,
		Entries: []proto.MLSRoleEntry{{AccountID: owner, Role: proto.MLSRoleOwner}}}
	for _, a := range admins {
		set.Entries = append(set.Entries, proto.MLSRoleEntry{AccountID: a, Role: proto.MLSRoleAdmin})
	}
	return set
}

// newRolesRoom is Alice (owner), Bob and Carol at epoch 1 in a room whose
// roles Alice set at create; admins are Alice's choice.
func newRolesRoom(t *testing.T, admins ...string) *room {
	t.Helper()
	e2eStateRoot(t)
	alice, bob, carol := newKeeper(t, e2eAlice), newKeeper(t, e2eBob), newKeeper(t, e2eCarol)
	id := alice.nextCommitID()
	built := commitOf(alice.must(proto.MLSGroupCreate, proto.MLSGroupCreateRequest{
		Permit: alice.permit(), OrgID: e2eOrg, ConversationID: e2eConv, ClientCommitID: id,
		Members: []proto.MLSMemberKeyPackage{bob.keyPackage(), carol.keyPackage()},
		Roles:   roleSet(e2eAlice, admins...),
	}))
	alice.confirm(id, proto.MLSCommitOutcomeAccepted, "")
	for _, k := range []*keeper{bob, carol} {
		k.must(proto.MLSJoin, proto.MLSJoinRequest{
			Permit: k.permit(), OrgID: e2eOrg, ConversationID: e2eConv, WelcomeB64: built.WelcomeB64,
		})
	}
	return &room{dm: &dm{alice: alice, bob: bob, seq: 1}, carol: carol}
}

func (k *keeper) publicKeyPEM() string {
	k.t.Helper()
	pem, err := keychain.GetPublicKey(k.store)
	if err != nil {
		k.t.Fatal(err)
	}
	return pem
}

// orgRemoval is what the server serves with a pending removal: the admin's
// signed statement and the admin's public key.
func orgRemoval(admin *keeper, removed string) proto.MLSOrgRemovalStatement {
	admin.t.Helper()
	st := admin.must(proto.OrgMemberRemovalSign, proto.OrgMemberRemovalSignRequest{
		OrgID: e2eOrg, RemovedAccountID: removed, AdminAccountID: admin.id,
	}).Data.(proto.OrgMemberRemovalSignResponseData).Statement
	st.AdminPublicKey = admin.publicKeyPEM()
	return st
}

func (k *keeper) leave() proto.MLSLeaveStatement {
	k.t.Helper()
	return k.must(proto.MLSLeaveRequestSign, proto.MLSLeaveRequestSignRequest{
		Permit: k.permit(), OrgID: e2eOrg, ConversationID: e2eConv,
	}).Data.(proto.MLSLeaveRequestSignResponseData).Statement
}

func (k *keeper) revokeOwnDevice() proto.MLSDeviceRevocation {
	k.t.Helper()
	return k.must(proto.MLSDeviceRevokeSign, proto.MLSDeviceRevokeSignRequest{
		AccountID: k.id, DeviceID: k.device,
	}).Data.(proto.MLSDeviceRevokeSignResponseData).Statement
}

func (k *keeper) buildRequest(expected uint64) proto.MLSCommitBuildRequest {
	return proto.MLSCommitBuildRequest{
		Permit: k.permit(), OrgID: e2eOrg, ConversationID: e2eConv,
		ClientCommitID: k.nextCommitID(), ExpectedEpoch: expected,
	}
}

func (k *keeper) accepted(req proto.MLSCommitBuildRequest) proto.MLSCommitResponseData {
	k.t.Helper()
	built := commitOf(k.must(proto.MLSCommitBuild, req))
	k.confirm(built.ClientCommitID, proto.MLSCommitOutcomeAccepted, "")
	return built
}

func assertCode(t *testing.T, resp proto.BaseResponse, code string) {
	t.Helper()
	if resp.Success || string(resp.ErrorCode) != code {
		t.Fatalf("response = %+v; want %s", resp, code)
	}
}

func roleEntries(set *proto.MLSRoleSet) []proto.MLSRoleEntry {
	out := slices.Clone(set.Entries)
	slices.SortFunc(out, func(a, b proto.MLSRoleEntry) int {
		switch {
		case a.AccountID < b.AccountID:
			return -1
		case a.AccountID > b.AccountID:
			return 1
		}
		return 0
	})
	return out
}

// ── Item 1: roles ───────────────────────────────────────────────────────

// Repro (item 1): Carol, a plain member, adds Dave. Before wave 5a Alice
// applied it: the group held no roles. Now Carol's own Keeper refuses to build
// it from the group's roles, and an admin's Add is applied by everyone.
func TestMLSRoles_APlainMemberCannotAddAndAnAdminCan(t *testing.T) {
	r := newRolesRoom(t, e2eBob)
	dave := newKeeper(t, e2eDave)
	req := r.carol.buildRequest(1)
	req.Add, req.UserInitiated = []proto.MLSMemberKeyPackage{dave.keyPackage()}, true
	assertCode(t, r.carol.call(proto.MLSCommitBuild, req), proto.ChatMLSErrorCodeCommitUnauthorized)
	if got := r.carol.status(); got.CommitPending {
		t.Fatal("a refused add left a pending commit")
	}

	req = r.bob.buildRequest(1)
	req.Add, req.UserInitiated = []proto.MLSMemberKeyPackage{dave.keyPackage()}, true
	add := r.bob.accepted(req)
	for _, k := range []*keeper{r.alice, r.carol} {
		if got := k.process(r.nextSeq(), 2, add.CommitB64); got.Epoch != 2 {
			t.Fatalf("%s applied the admin's add at %+v", k.id[:8], got)
		}
	}
}

// The status names the rules and the roles from the group context.
func TestMLSRoles_StatusReportsTheAuthority(t *testing.T) {
	r := newRolesRoom(t, e2eBob)
	for _, k := range []*keeper{r.alice, r.bob, r.carol} {
		got := k.status()
		if got.Authority != "roles" || !got.RolesMigratable ||
			!slices.Equal(got.Roles, roleEntries(roleSet(e2eAlice, e2eBob))) {
			t.Fatalf("%s status = %+v", k.id[:8], got)
		}
	}
	legacy := newRoom(t)
	if got := legacy.carol.status(); got.Authority != "legacy_temporary" || len(got.Roles) != 0 || !got.RolesMigratable {
		t.Fatalf("a legacy room's status = %+v", got)
	}
}

// A roles Commit: the owner transfers ownership (the old owner stays an
// admin). An admin cannot change the roles; after the transfer the old owner,
// now an admin, cannot either, and the new owner can.
func TestMLSRoles_OwnershipTransferIsARolesCommit(t *testing.T) {
	r := newRolesRoom(t, e2eBob)
	req := r.bob.buildRequest(1)
	req.SetRoles, req.UserInitiated = roleSet(e2eBob, e2eAlice), true
	assertCode(t, r.bob.call(proto.MLSCommitBuild, req), proto.ChatMLSErrorCodeCommitUnauthorized)

	req = r.alice.buildRequest(1)
	req.SetRoles = roleSet(e2eCarol, e2eAlice)
	assertCode(t, r.alice.call(proto.MLSCommitBuild, req), proto.ChatMLSErrorCodeCommitUnauthorized)

	req = r.alice.buildRequest(1)
	req.SetRoles, req.UserInitiated = roleSet(e2eCarol, e2eAlice), true
	transfer := r.alice.accepted(req)
	for _, k := range []*keeper{r.bob, r.carol} {
		k.process(r.nextSeq(), 2, transfer.CommitB64)
		if got := k.status(); !slices.Equal(got.Roles, roleEntries(roleSet(e2eCarol, e2eAlice))) {
			t.Fatalf("%s roles after the transfer = %+v", k.id[:8], got.Roles)
		}
	}
	req = r.alice.buildRequest(2)
	req.SetRoles, req.UserInitiated = roleSet(e2eAlice), true
	assertCode(t, r.alice.call(proto.MLSCommitBuild, req), proto.ChatMLSErrorCodeCommitUnauthorized)
	req = r.carol.buildRequest(2)
	req.SetRoles, req.UserInitiated = roleSet(e2eCarol, e2eAlice, e2eBob), true
	grant := r.carol.accepted(req)
	r.alice.process(r.nextSeq(), 3, grant.CommitB64)
}

// A legacy room's owner sets its roles on its first Commit; a member cannot,
// and until then the room is legacy_temporary.
func TestMLSRoles_ALegacyRoomMigratesOnTheOwnersCommit(t *testing.T) {
	r := newRoom(t)
	req := r.bob.buildRequest(2)
	req.SetRoles = roleSet(e2eBob)
	assertCode(t, r.bob.call(proto.MLSCommitBuild, req), proto.ChatMLSErrorCodeCommitUnauthorized)

	req = r.alice.buildRequest(2)
	req.SetRoles = roleSet(e2eAlice, e2eCarol)
	migrate := r.alice.accepted(req)
	for _, k := range []*keeper{r.bob, r.carol} {
		k.process(r.nextSeq(), 3, migrate.CommitB64)
		if got := k.status(); got.Authority != "roles" {
			t.Fatalf("%s after the migration = %+v", k.id[:8], got)
		}
	}
	// Now a plain member's Add is refused where the legacy room took it.
	dave := newKeeper(t, e2eDave)
	add := r.bob.buildRequest(3)
	add.Add, add.UserInitiated = []proto.MLSMemberKeyPackage{dave.keyPackage()}, true
	assertCode(t, r.bob.call(proto.MLSCommitBuild, add), proto.ChatMLSErrorCodeCommitUnauthorized)
}

// A DM carries the DM marker and adds nobody after its create.
func TestMLSRoles_ADMAddsNobody(t *testing.T) {
	e2eStateRoot(t)
	alice, bob := newKeeper(t, e2eAlice), newKeeper(t, e2eBob)
	id := alice.nextCommitID()
	built := commitOf(alice.must(proto.MLSGroupCreate, proto.MLSGroupCreateRequest{
		Permit: alice.permit(), OrgID: e2eOrg, ConversationID: e2eConv, ClientCommitID: id,
		Members: []proto.MLSMemberKeyPackage{bob.keyPackage()},
		Roles:   &proto.MLSRoleSet{Kind: proto.MLSRolesKindDM, Entries: []proto.MLSRoleEntry{}},
	}))
	alice.confirm(id, proto.MLSCommitOutcomeAccepted, "")
	bob.must(proto.MLSJoin, proto.MLSJoinRequest{Permit: bob.permit(), OrgID: e2eOrg, ConversationID: e2eConv, WelcomeB64: built.WelcomeB64})
	if got := bob.status(); got.Authority != "dm" {
		t.Fatalf("bob's DM status = %+v", got)
	}
	carol := newKeeper(t, e2eCarol)
	req := alice.buildRequest(1)
	req.Add, req.UserInitiated = []proto.MLSMemberKeyPackage{carol.keyPackage()}, true
	assertCode(t, alice.call(proto.MLSCommitBuild, req), proto.ChatMLSErrorCodeCommitUnauthorized)
}

// An admin removes a member; an admin cannot remove the owner; a member
// cannot remove anybody on its role.
func TestMLSRoles_RoleBasedRemoves(t *testing.T) {
	r := newRolesRoom(t, e2eBob)
	req := r.carol.buildRequest(1)
	req.RemoveAccountIDs, req.UserInitiated = []string{e2eBob}, true
	assertCode(t, r.carol.call(proto.MLSCommitBuild, req), proto.ChatMLSErrorCodeCommitUnauthorized)
	req = r.bob.buildRequest(1)
	req.RemoveAccountIDs, req.UserInitiated = []string{e2eAlice}, true
	assertCode(t, r.bob.call(proto.MLSCommitBuild, req), proto.ChatMLSErrorCodeCommitUnauthorized)
	req = r.bob.buildRequest(1)
	req.RemoveAccountIDs, req.UserInitiated = []string{e2eCarol}, true
	removed := r.bob.accepted(req)
	if got := r.alice.process(r.nextSeq(), 2, removed.CommitB64); got.Epoch != 2 {
		t.Fatalf("alice applied the admin's remove at %+v", got)
	}
	if got := r.carol.process(r.nextSeq(), 2, removed.CommitB64); !got.Removed {
		t.Fatalf("carol processed her removal as %+v", got)
	}
}

// ── Item 2: the admin-signed org removal ────────────────────────────────

// Repro (item 2): before wave 5a the permit's pending removal alone let any
// member build and every member apply the Remove. Now the server's word only
// latches sends; the Remove needs an org admin's signed statement, which any
// member's automation can then carry and every member verifies from the
// Commit itself, catch-up included.
func TestMLSRoles_AnOrgRemovalNeedsTheAdminsStatement(t *testing.T) {
	r := newRolesRoom(t)
	admin := newKeeper(t, e2eAdmin)

	// Omitted: the server lists Carol as departed but serves no statement.
	req := r.bob.buildRequest(1)
	req.Permit, req.RemoveAccountIDs = r.bob.permit(e2eCarol), []string{e2eCarol}
	assertCode(t, r.bob.call(proto.MLSCommitBuild, req), proto.ChatMLSErrorCodeCommitUnauthorized)
	r.bob.refused(proto.MLSEncrypt, r.bob.encryptRequest(messageID(1), 1, "hi", e2eCarol),
		proto.ChatMLSErrorCodeRotationPending)

	// Tampered: the statement names Carol but its signature is over Bob.
	forged := orgRemoval(admin, e2eBob)
	forged.RemovedAccountID = e2eCarol
	req.ClientCommitID, req.OrgRemovalStatements = r.bob.nextCommitID(), []proto.MLSOrgRemovalStatement{forged}
	assertCode(t, r.bob.call(proto.MLSCommitBuild, req), proto.ChatMLSErrorCodeStatementUnverified)

	// Another organization's statement.
	other := orgRemoval(admin, e2eCarol)
	other.OrgID = e2eConv2
	req.ClientCommitID, req.OrgRemovalStatements = r.bob.nextCommitID(), []proto.MLSOrgRemovalStatement{other}
	assertCode(t, r.bob.call(proto.MLSCommitBuild, req), proto.ChatMLSErrorCodeStatementUnverified)

	// The genuine statement: Bob, a plain member, carries it out.
	req.ClientCommitID, req.OrgRemovalStatements = r.bob.nextCommitID(), []proto.MLSOrgRemovalStatement{orgRemoval(admin, e2eCarol)}
	removed := r.bob.accepted(req)
	// Alice has no pending removal in her permit and no attestation on the
	// row: the statement inside the Commit is what she verifies.
	if got := r.alice.process(r.nextSeq(), 2, removed.CommitB64); got.Epoch != 2 {
		t.Fatalf("alice applied the signed removal at %+v", got)
	}
	if got := r.carol.process(r.nextSeq(), 2, removed.CommitB64); !got.Removed {
		t.Fatalf("carol processed her removal as %+v", got)
	}
	r.bob.must(proto.MLSEncrypt, r.bob.encryptRequest(messageID(1), 2, "carol is gone", e2eCarol))
}

// A malicious server serves the builder one admin key and a receiver pinned
// another: the receiver refuses the Remove and latches, naming the committer.
// The admin set is server-attested, so the first key each device sees is
// taken on trust (TOFU); a changed one is not.
func TestMLSRoles_AnAdminKeyThatChangedIsRefused(t *testing.T) {
	r := newRolesRoom(t)
	admin := newKeeper(t, e2eAdmin)
	impostor := newKeeper(t, e2eAdmin)
	// Alice saw the genuine admin key first, and pinned it on first use.
	now := time.Now().Unix()
	if err := keychain.SavePeerKeyPin(r.alice.store, e2eAlice, e2eAdmin, keychain.PeerKeyPin{
		V: keychain.PeerKeyPinVersion, Fingerprint: crypto.AccountKeyFingerprint([]byte(admin.publicKeyPEM())),
		State: keychain.PeerKeyPinStateTOFU, FirstSeenAt: now, LastSeenAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	req := r.bob.buildRequest(1)
	req.Permit, req.RemoveAccountIDs = r.bob.permit(e2eCarol), []string{e2eCarol}
	req.OrgRemovalStatements = []proto.MLSOrgRemovalStatement{orgRemoval(impostor, e2eCarol)}
	removed := r.bob.accepted(req)
	got := latchedData(t, r.alice.call(proto.MLSProcess, r.alice.processRequest(r.nextSeq(), 2, removed.CommitB64)))
	if got.RekeyCause != proto.ChatStateRekeyCauseUnauthorizedCommit || got.RekeyCommitterAccountID != e2eBob {
		t.Fatalf("latch detail = %+v", got)
	}
}

// Replayed: the server serves a statement again after the account came back.
// The Keeper accepts it (a statement names an account, not an epoch): the
// stated limit, pinned so it is not mistaken for a guarantee.
func TestMLSRoles_AReplayedOrgRemovalIsAcceptedAsStated(t *testing.T) {
	r := newRolesRoom(t)
	admin := newKeeper(t, e2eAdmin)
	old := orgRemoval(admin, e2eCarol)
	req := r.bob.buildRequest(1)
	req.RemoveAccountIDs, req.OrgRemovalStatements = []string{e2eCarol}, []proto.MLSOrgRemovalStatement{old}
	first := r.bob.accepted(req)
	r.alice.process(r.nextSeq(), 2, first.CommitB64)

	add := r.alice.buildRequest(2)
	add.Add, add.UserInitiated = []proto.MLSMemberKeyPackage{r.carol.keyPackage()}, true
	readded := r.alice.accepted(add)
	r.bob.process(r.nextSeq(), 3, readded.CommitB64)

	again := r.bob.buildRequest(3)
	again.RemoveAccountIDs, again.OrgRemovalStatements = []string{e2eCarol}, []proto.MLSOrgRemovalStatement{old}
	replayed := r.bob.accepted(again)
	if got := r.alice.process(r.nextSeq(), 4, replayed.CommitB64); got.Epoch != 4 {
		t.Fatalf("alice applied the replayed statement at %+v", got)
	}
}

// ── Item 3: leave and device revocation ─────────────────────────────────

// Repro (item 3): there was no leave. Carol signs her request to leave; Bob,
// a plain member, removes her on its strength, and Alice applies it from the
// statement inside the Commit. The request of another conversation is
// refused.
func TestMLSRoles_ASignedLeaveIsCarriedOutByAnyMember(t *testing.T) {
	r := newRolesRoom(t)
	leave := r.carol.leave()
	if leave.ConversationID != e2eConv || leave.AccountID != e2eCarol {
		t.Fatalf("leave statement = %+v", leave)
	}

	replayed := leave
	replayed.ConversationID = e2eConv2
	req := r.bob.buildRequest(1)
	req.Permit, req.RemoveAccountIDs = r.bob.permit(e2eCarol), []string{e2eCarol}
	req.LeaveStatements = []proto.MLSLeaveStatement{replayed}
	assertCode(t, r.bob.call(proto.MLSCommitBuild, req), proto.ChatMLSErrorCodeStatementUnverified)

	req.ClientCommitID, req.LeaveStatements = r.bob.nextCommitID(), []proto.MLSLeaveStatement{leave}
	removed := r.bob.accepted(req)
	if got := r.alice.process(r.nextSeq(), 2, removed.CommitB64); got.Epoch != 2 {
		t.Fatalf("alice applied the leave at %+v", got)
	}
	if got := r.carol.process(r.nextSeq(), 2, removed.CommitB64); !got.Removed {
		t.Fatalf("carol processed her leave as %+v", got)
	}

	// A leave signed by somebody else's key does not remove Bob.
	forged := leave
	forged.AccountID = e2eBob
	req = r.alice.buildRequest(2)
	req.RemoveAccountIDs, req.LeaveStatements = []string{e2eBob}, []proto.MLSLeaveStatement{forged}
	assertCode(t, r.alice.call(proto.MLSCommitBuild, req), proto.ChatMLSErrorCodeStatementUnverified)
}

// Carol revokes her device. The permit names the revocation, which latches
// sends while the leaf remains; Bob removes exactly that leaf on the signed
// revocation, and Alice applies it and may send again.
func TestMLSRoles_ASignedDeviceRevocationRemovesThatLeaf(t *testing.T) {
	r := newRolesRoom(t)
	revocation := r.carol.revokeOwnDevice()
	ref := proto.MLSDeviceRef{AccountID: e2eCarol, DeviceID: r.carol.device}
	r.alice.revoked = []proto.MLSDeviceRef{ref}
	r.alice.refused(proto.MLSEncrypt, r.alice.encryptRequest(messageID(1), 1, "to carol's old device"),
		proto.ChatMLSErrorCodeRotationPending)
	if got := r.alice.status(); !slices.Equal(got.DeviceRevokeLatch, []proto.MLSDeviceRef{ref}) {
		t.Fatalf("alice's device revoke latch = %+v", got.DeviceRevokeLatch)
	}

	req := r.bob.buildRequest(1)
	req.RevokeDevices = []proto.MLSDeviceRef{ref}
	assertCode(t, r.bob.call(proto.MLSCommitBuild, req), proto.ChatMLSErrorCodeCommitUnauthorized)
	req.ClientCommitID, req.DeviceRevocations = r.bob.nextCommitID(), []proto.MLSDeviceRevocation{revocation}
	removed := r.bob.accepted(req)
	if got := r.alice.process(r.nextSeq(), 2, removed.CommitB64); got.Epoch != 2 {
		t.Fatalf("alice applied the revocation at %+v", got)
	}
	r.alice.must(proto.MLSEncrypt, r.alice.encryptRequest(messageID(1), 2, "carol's old device is out"))
	if got := r.alice.status(); len(got.DeviceRevokeLatch) != 0 {
		t.Fatalf("the latch outlived the leaf: %+v", got.DeviceRevokeLatch)
	}
}

// A tampered Commit: the server strips the statements from a signed Remove.
// The committer's signature covers them, so the Commit does not open and
// nothing is applied.
func TestMLSRoles_AStrippedStatementBreaksTheCommit(t *testing.T) {
	r := newRolesRoom(t)
	req := r.bob.buildRequest(1)
	req.RemoveAccountIDs, req.LeaveStatements = []string{e2eCarol}, []proto.MLSLeaveStatement{r.carol.leave()}
	removed := r.bob.accepted(req)
	raw, err := base64.StdEncoding.DecodeString(removed.CommitB64)
	if err != nil {
		t.Fatal(err)
	}
	at := slices.Index(raw, byte('{'))
	if at < 0 {
		t.Fatal("the commit carries no statements")
	}
	raw[at+1] ^= 0x01
	resp := r.alice.call(proto.MLSProcess, r.alice.processRequest(r.nextSeq(), 2, base64.StdEncoding.EncodeToString(raw)))
	if resp.Success {
		t.Fatal("a commit whose statements were altered was applied")
	}
	if got := r.alice.status(); got.Epoch != 1 {
		t.Fatalf("a refused commit moved alice to %+v", got)
	}
}
