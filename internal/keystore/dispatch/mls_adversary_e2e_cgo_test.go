//go:build mls && cgo

// Receiving-side refusals against a malicious client (wave 5c item 8).
//
// Mallory's device is played by mls/examples/adversary.rs: mls-rs with its
// permissive DefaultMlsRules and Mallory's own leaf key and declaration, so
// every Commit it builds is cryptographically valid and signed by a real
// member, and a normal Keeper could never have built it. Alice (the room's
// owner) and Carol (a member) are normal Keepers and receive it through
// mls_process: Alice live, at the next epoch, and Carol on catch-up, one
// lawful row behind, both rows carrying the server's attestation.
//
// Every refusal leaves the receiver where it was: the same state files byte
// for byte, the same keyring entries (pins included) but for the one field a
// refusal writes, the anchor's sync_block (N3), and the same epoch and roles.
// The conversation is not latched: it stops at that epoch, refuses to send,
// and is still read as usual. Each case has a positive control: the same
// client's lawful Commit is applied, so a refusal is never the fixture's
// fault.

package dispatch

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dragpass/keeper/config"
	"github.com/dragpass/keeper/internal/keystore/chatstate"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/mls/mlsadversary"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

const advMallory = "f6666666-6666-4666-8666-666666666666"

// advRoom is Alice (owner), Carol (member) and Mallory (admin or member) at
// epoch 1, Mallory's device being the adversary.
type advRoom struct {
	t                     *testing.T
	alice, carol, mallory *keeper
	adv                   *mlsadversary.Client
	seq                   uint64
}

func leafKeyOf(t *testing.T, k *keeper) keychain.MLSLeafKey {
	t.Helper()
	leaf, found, err := keychain.GetMLSLeafKey(k.store)
	if err != nil || !found {
		t.Fatalf("leaf key of %s: %v", k.id[:8], err)
	}
	return leaf
}

func advB64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func unb64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func newAdvRoom(t *testing.T, malloryIsAdmin bool) *advRoom {
	t.Helper()
	e2eStateRoot(t)
	alice, carol, mallory := newKeeper(t, e2eAlice), newKeeper(t, e2eCarol), newKeeper(t, advMallory)
	adv := mlsadversary.Start(t, leafKeyOf(t, mallory), true)
	var admins []string
	if malloryIsAdmin {
		admins = []string{advMallory}
	}
	id := alice.nextCommitID()
	built := commitOf(alice.must(proto.MLSGroupCreate, proto.MLSGroupCreateRequest{
		Permit: alice.permit(), OrgID: e2eOrg, ConversationID: e2eConv, ClientCommitID: id,
		Members: []proto.MLSMemberKeyPackage{
			carol.keyPackage(),
			{AccountID: advMallory, DeviceID: mallory.device, KeyPackageB64: advB64(adv.KeyPackage())},
		},
		Roles: roleSet(e2eAlice, admins...),
	}))
	alice.confirm(id, proto.MLSCommitOutcomeAccepted, "")
	carol.must(proto.MLSJoin, proto.MLSJoinRequest{
		Permit: carol.permit(), OrgID: e2eOrg, ConversationID: e2eConv, WelcomeB64: built.WelcomeB64,
	})
	if got := adv.Join(unb64(t, built.WelcomeB64)); got != 1 {
		t.Fatalf("the adversary joined at epoch %d", got)
	}
	return &advRoom{t: t, alice: alice, carol: carol, mallory: mallory, adv: adv, seq: 1}
}

func (r *advRoom) nextSeq() uint64 {
	r.seq++
	return r.seq
}

// lawfulRow is Alice's key update at epoch 1, applied by Alice and the
// adversary and left for Carol to catch up on.
func (r *advRoom) lawfulRow() (seq uint64, commitB64 string) {
	r.t.Helper()
	built := r.alice.buildUpdate(1)
	r.alice.confirm(built.ClientCommitID, proto.MLSCommitOutcomeAccepted, "")
	if got := r.adv.Process(unb64(r.t, built.CommitB64)); got != 2 {
		r.t.Fatalf("the adversary followed the update to epoch %d", got)
	}
	return r.nextSeq(), built.CommitB64
}

// receiverState is everything a refused Commit must leave as it was. The
// group state (epoch, tree, roles) and the record's generation are in the
// state files; the pins and the newest-declaration records in the keyring; the
// epoch, generation, watermark and rekey fields of the rollback anchor in
// anchors.
type receiverState struct {
	files   map[string][]byte
	secrets map[string]string
	anchors map[string]chatstate.Anchor
}

func stateOf(t *testing.T, k *keeper) receiverState {
	t.Helper()
	s := receiverState{files: map[string][]byte{}, secrets: map[string]string{}, anchors: map[string]chatstate.Anchor{}}
	root := os.Getenv(chatstate.RootEnvVar)
	if err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || strings.HasSuffix(path, ".lock") {
			return err
		}
		b, err := os.ReadFile(path)
		s.files[path] = b
		return err
	}); err != nil {
		t.Fatal(err)
	}
	for key, value := range k.store.Snapshot() {
		if !strings.HasPrefix(key, config.Service+"|"+config.ChatStateAnchorPrefix) {
			s.secrets[key] = value
			continue
		}
		var a chatstate.Anchor
		if err := json.Unmarshal([]byte(value), &a); err != nil {
			t.Fatal(err)
		}
		// The sync block is the one thing a refusal writes (anchor
		// sync_block); the rekey latch fields must stay as they were.
		a.SyncBlock = nil
		s.anchors[key] = a
	}
	if len(s.anchors) != 1 {
		t.Fatalf("%s holds %d chat anchors, want 1", k.id[:8], len(s.anchors))
	}
	return s
}

func assertUnchanged(t *testing.T, who string, before, after receiverState) {
	t.Helper()
	if !maps.EqualFunc(before.files, after.files, bytes.Equal) {
		t.Errorf("%s: the refusal changed the state files", who)
	}
	if !maps.Equal(before.secrets, after.secrets) {
		t.Errorf("%s: the refusal changed a keyring entry (a pin or a record)", who)
	}
	if !maps.Equal(before.anchors, after.anchors) {
		t.Errorf("%s: the refusal moved the anchor or its watermark: %+v -> %+v", who, before.anchors, after.anchors)
	}
}

// refusal is how a receiver must refuse: the row refused as unauthorized,
// naming Mallory (block true), or refused with code (the leaf check), both
// stopping the conversation at that epoch without a latch.
type refusal struct {
	block bool
	code  string
}

var blockedUnauthorized = refusal{block: true}

func (r *advRoom) assertRefused(who *keeper, req proto.MLSProcessRequest, want refusal) {
	r.t.Helper()
	st := who.status()
	if st.Epoch != 2 || st.NeedsRekey || len(st.Roles) == 0 {
		r.t.Fatalf("%s before the malicious commit = %+v", who.id[:8], st)
	}
	before := stateOf(r.t, who)
	for _, a := range before.anchors {
		if a.Epoch != 2 {
			r.t.Fatalf("%s's anchor is at epoch %d before the commit", who.id[:8], a.Epoch)
		}
	}
	resp := who.call(proto.MLSProcess, req)
	name := who.id[:8]
	if want.block {
		got := blockedData(r.t, resp)
		if got.Cause != proto.ChatStateRekeyCauseUnauthorizedCommit || got.CommitterAccountID != advMallory || got.Epoch != 3 {
			r.t.Fatalf("%s blocked %+v; want unauthorized_commit at epoch 3 naming mallory", name, got)
		}
	} else if resp.Success || string(resp.ErrorCode) != want.code {
		r.t.Fatalf("%s answered %+v; want %s", name, resp, want.code)
	}
	st = who.status()
	if st.NeedsRekey || st.SyncBlocked == nil || st.SyncBlocked.Epoch != 3 || st.Epoch != 2 {
		r.t.Fatalf("%s status after the refusal = %+v; want blocked at 3, not latched", name, st)
	}
	who.refused(proto.MLSEncrypt, who.encryptRequest(messageID(7), 2, "not on top of a refused commit"),
		proto.ChatMLSErrorCodeSyncBlocked)
	assertUnchanged(r.t, name, before, stateOf(r.t, who))
}

// deliver hands the malicious Commit to Alice live and to Carol on catch-up,
// after the lawful row, both with the server's attestation of the member set
// the row declares.
func (r *advRoom) deliver(lawfulSeq uint64, lawfulB64 string, commit []byte, alice, carol refusal,
	rotation ...proto.KeyRotationStatement,
) {
	r.t.Helper()
	members := []string{e2eAlice, e2eCarol, advMallory}
	seq := r.nextSeq()
	req := r.alice.processRequest(seq, 3, advB64(commit))
	req.CommitAttestation, req.RotationStatements = attested(members...), rotation
	r.assertRefused(r.alice, req, alice)

	lawful := r.carol.processRequest(lawfulSeq, 2, lawfulB64)
	lawful.CommitAttestation = attested(members...)
	if got := r.carol.must(proto.MLSProcess, lawful).Data.(proto.MLSProcessResponseData); got.Epoch != 2 {
		r.t.Fatalf("carol caught up on the lawful row at %+v", got)
	}
	req = r.carol.processRequest(seq, 3, advB64(commit))
	req.CommitAttestation, req.RotationStatements = attested(members...), rotation
	r.assertRefused(r.carol, req, carol)
}

// applied is the positive control: Alice applies a Commit from the same
// client.
func (r *advRoom) applied(commit []byte, rotation ...proto.KeyRotationStatement) {
	r.t.Helper()
	req := r.alice.processRequest(r.nextSeq(), 3, advB64(commit))
	req.RotationStatements = rotation
	if got := r.alice.must(proto.MLSProcess, req).Data.(proto.MLSProcessResponseData); got.Epoch != 3 {
		r.t.Fatalf("alice applied the lawful commit at %+v", got)
	}
}

func keyPackageBytes(t *testing.T, kp proto.MLSMemberKeyPackage) []byte {
	return unb64(t, kp.KeyPackageB64)
}

// (a) A plain member seats Carol's recovered identity in place of her leaf.
// Only the room's owner or an admin may (Q2, Q4 of wave 5b): refused and
// blocked at its epoch. Carol's own old device refuses it at the leaf check, since the
// leaf claims her account under another account key.
func TestMLSAdversary_APlainMemberSeatsARecoveredIdentity(t *testing.T) {
	for _, admin := range []bool{false, true} {
		r := newAdvRoom(t, admin)
		lawfulSeq, lawfulB64 := r.lawfulRow()
		carol2, chain := recoveredKeeper(t, r.carol, e2eDevice2)
		oldCarol, _, _ := keychain.GetMLSLeafNewest(r.alice.store, r.alice.id, r.carol.id)
		carol2.declare(proto.MLSLeafReasonRotate, oldCarol.NotBefore+60)
		commit, _ := r.adv.Build(mlsadversary.Commit{
			Removes: []uint32{r.adv.IndexOf(e2eCarol, r.carol.device)},
			Adds:    [][]byte{keyPackageBytes(t, carol2.keyPackage())},
		})
		if admin {
			r.applied(commit, chain)
			continue
		}
		r.deliver(lawfulSeq, lawfulB64, commit, blockedUnauthorized,
			refusal{code: proto.ChatMLSErrorCodeLeafUntrusted}, chain)
	}
}

// (b) Two devices of one account in one Commit, from an admin, who may add.
// The leaf check refuses it first: two entering declarations of one account
// cannot both be its newest (mls_leaf_verify.go checkNewest); the row is
// blocked with cause leaf_untrusted; the Q14 rule behind it is pinned by the Rust session test
// two_devices_of_one_account_in_one_commit_are_refused and the Go unit test.
func TestMLSAdversary_TwoDevicesOfOneAccountInOneCommit(t *testing.T) {
	r := newAdvRoom(t, true)
	lawfulSeq, lawfulB64 := r.lawfulRow()
	dave := newKeeper(t, e2eDave)
	dave2 := newTakeoverKeeper(t, dave, e2eDevice2)
	oldDave := leafKeyOf(t, dave)
	var decl proto.MLSLeafDeclaration
	if err := json.Unmarshal(oldDave.Declaration, &struct {
		Declaration *proto.MLSLeafDeclaration `json:"declaration"`
	}{&decl}); err != nil {
		t.Fatal(err)
	}
	dave2.declare(proto.MLSLeafReasonRotate, decl.NotBefore+60)
	commit, _ := r.adv.Build(mlsadversary.Commit{Adds: [][]byte{
		keyPackageBytes(t, dave.keyPackage()), keyPackageBytes(t, dave2.keyPackage()),
	}})
	untrusted := refusal{code: proto.ChatMLSErrorCodeLeafUntrusted}
	r.deliver(lawfulSeq, lawfulB64, commit, untrusted, untrusted)

	// Control: one of them is applied.
	one, _ := r.adv.Build(mlsadversary.Commit{Adds: [][]byte{keyPackageBytes(t, dave2.keyPackage())}})
	r.applied(one)
}

// (c) An admin adds Carol's second device next to the one she holds. After
// the Commit her account would hold two leaves (Q14): refused and blocked by
// both receivers.
func TestMLSAdversary_AnExistingLeafAndANewLeafOfOneAccount(t *testing.T) {
	r := newAdvRoom(t, true)
	lawfulSeq, lawfulB64 := r.lawfulRow()
	carol2 := newTakeoverKeeper(t, r.carol, e2eDevice2)
	oldCarol, _, _ := keychain.GetMLSLeafNewest(r.alice.store, r.alice.id, r.carol.id)
	carol2.declare(proto.MLSLeafReasonRotate, oldCarol.NotBefore+60)
	kp := keyPackageBytes(t, carol2.keyPackage())
	commit, _ := r.adv.Build(mlsadversary.Commit{Adds: [][]byte{kp}})
	r.deliver(lawfulSeq, lawfulB64, commit, blockedUnauthorized, blockedUnauthorized)
}

// (d) A plain member adds somebody to a room with roles: refused and blocked.
func TestMLSAdversary_APlainMemberAdds(t *testing.T) {
	for _, admin := range []bool{false, true} {
		r := newAdvRoom(t, admin)
		lawfulSeq, lawfulB64 := r.lawfulRow()
		dave := newKeeper(t, e2eDave)
		commit, _ := r.adv.Build(mlsadversary.Commit{Adds: [][]byte{keyPackageBytes(t, dave.keyPackage())}})
		if admin {
			r.applied(commit)
			continue
		}
		r.deliver(lawfulSeq, lawfulB64, commit, blockedUnauthorized, blockedUnauthorized)
	}
}

// (e) A role change by somebody who is not the owner: an admin making itself
// owner, and a member making itself admin. Refused and blocked. Control: the
// owner's own change is applied (TestMLSRoles_* covers that build side).
func TestMLSAdversary_ARoleChangeByANonOwner(t *testing.T) {
	for name, tc := range map[string]struct {
		admin bool
		roles chatstate.Roles
	}{
		"admin takes the room": {true, chatstate.Roles{Kind: chatstate.RolesKindRoom, Owner: advMallory, Admins: []string{e2eAlice}}},
		"member grants itself": {false, chatstate.Roles{Kind: chatstate.RolesKindRoom, Owner: e2eAlice, Admins: []string{advMallory}}},
	} {
		t.Run(name, func(t *testing.T) {
			r := newAdvRoom(t, tc.admin)
			lawfulSeq, lawfulB64 := r.lawfulRow()
			commit, _ := r.adv.Build(mlsadversary.Commit{Roles: tc.roles.Encode()})
			r.deliver(lawfulSeq, lawfulB64, commit, blockedUnauthorized, blockedUnauthorized)
		})
	}
}

// (f) A Remove with no authority: a plain member removes Carol with no
// statement. Refused and blocked by Alice, and by Carol, the one removed.
// Control: an admin's removal of the plain member is applied.
func TestMLSAdversary_ARemoveWithoutAuthority(t *testing.T) {
	r := newAdvRoom(t, false)
	lawfulSeq, lawfulB64 := r.lawfulRow()
	commit, _ := r.adv.Build(mlsadversary.Commit{Removes: []uint32{r.adv.IndexOf(e2eCarol, r.carol.device)}})
	r.deliver(lawfulSeq, lawfulB64, commit, blockedUnauthorized, blockedUnauthorized)

	admin := newAdvRoom(t, true)
	admin.lawfulRow()
	removal, _ := admin.adv.Build(mlsadversary.Commit{Removes: []uint32{admin.adv.IndexOf(e2eCarol, admin.carol.device)}})
	admin.applied(removal)
}

// Q10 on receipt, from a client that carries what a normal Keeper refuses to
// build: a plain member removes Carol on an org admin's statement signed 31
// days ago. The statement is past its window, so the Remove rests on nothing:
// refused and blocked. Control: the same statement 29 days old is applied.
func TestMLSAdversary_AnExpiredStatementCarriesNoRemove(t *testing.T) {
	for _, age := range []time.Duration{31 * day, 29 * day} {
		r := newAdvRoom(t, false)
		lawfulSeq, lawfulB64 := r.lawfulRow()
		admin := newKeeper(t, e2eAdmin)
		st := admin.signedAgo(age, func() any { return orgRemoval(admin, e2eCarol) }).(proto.MLSOrgRemovalStatement)
		aad, err := proto.MLSCommitEvidence{OrgRemovals: []proto.MLSOrgRemovalStatement{st}}.Encode()
		if err != nil {
			t.Fatal(err)
		}
		commit, _ := r.adv.Build(mlsadversary.Commit{
			Removes: []uint32{r.adv.IndexOf(e2eCarol, r.carol.device)}, AAD: aad,
		})
		if age < 30*day {
			r.applied(commit)
			continue
		}
		r.deliver(lawfulSeq, lawfulB64, commit, blockedUnauthorized, blockedUnauthorized)
	}
}

// Q11 end to end: a KeyPackage built by a client without the roles extension,
// as a Keeper before wave 5 built them, sits in Carol's pool. The sweep drops
// it and keeps the one this Keeper built; a second sweep drops nothing.
func TestMLSAdversary_ThePoolSweepDropsAnOldKeepersKeyPackage(t *testing.T) {
	e2eStateRoot(t)
	carol := newKeeper(t, e2eCarol)
	carol.keyPackage()
	old := mlsadversary.Start(t, leafKeyOf(t, carol), false)
	entry, ref, notAfter := old.KeyPackageEntry()
	store, err := chatstate.Open(carol.store, carol.id)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	leaf := leafKeyOf(t, carol)
	var decl struct {
		Declaration proto.MLSLeafDeclaration `json:"declaration"`
	}
	if err := json.Unmarshal(leaf.Declaration, &decl); err != nil {
		t.Fatal(err)
	}
	if err := store.AddKeyPackages([]chatstate.KeyPackagePoolEntry{{
		Ref: ref, NotAfter: notAfter, Leaf: decl.Declaration.SignatureKeyFingerprint, Private: entry,
	}}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if n := carol.poolSize(); n != 2 {
		t.Fatalf("pool size before the sweep = %d", n)
	}
	sweep := func() proto.MLSKeyPackagePoolSweepResponseData {
		return carol.must(proto.MLSKeyPackagePoolSweep, proto.MLSKeyPackagePoolSweepRequest{AccountID: carol.id}).
			Data.(proto.MLSKeyPackagePoolSweepResponseData)
	}
	if got := sweep(); got.Dropped != 1 || got.Remaining != 1 {
		t.Fatalf("sweep = %+v; want the old KeyPackage dropped and one left", got)
	}
	if got := sweep(); got.Dropped != 0 || got.Remaining != 1 {
		t.Fatalf("a repeated sweep = %+v", got)
	}
	if _, err := store.LookupKeyPackage([][]byte{ref}, time.Now()); err == nil {
		t.Fatal("the old KeyPackage survived the sweep")
	}
}
