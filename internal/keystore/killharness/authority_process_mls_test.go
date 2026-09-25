//go:build mls && cgo

// The Commit authority rules and the fork ring in the Keeper binary, with
// every permit and every commit attestation signed by the test server key the
// Keeper's own verifier checks (chatstate/authority.go, design Q4, Q16).

package killharness

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"slices"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/proto"
)

const hCarol = "c3333333-3333-4333-8333-333333333333"

// attestation is what ariadne signs on a handshake row: the member set the
// row's Commit declared, bound to the Commit and its epoch.
func attestation(t *testing.T, epoch uint64, commitB64 string, members ...string) *proto.MLSCommitAttestation {
	t.Helper()
	commit, err := base64.StdEncoding.DecodeString(commitB64)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(commit)
	a := proto.MLSCommitAttestation{MemberAccountIDs: slices.Sorted(slices.Values(members)), ServerKeyVersion: 1}
	a.Signature = sign(t, proto.MLSCommitAttestationCanonical(hConv, epoch, hex.EncodeToString(sum[:]), a))
	return &a
}

func (d *device) attestedProcess(seq, epoch uint64, commitB64 string, members ...string) proto.MLSProcessRequest {
	req := d.processRequest(seq, epoch, commitB64)
	req.CommitAttestation = attestation(d.t, epoch, commitB64, members...)
	return req
}

// threeParty is Alice, Bob and Carol at epoch 1, every process stopped.
type threeParty struct {
	alice, bob, carol *device
	seq               uint64
}

func newThreeParty(t *testing.T) *threeParty {
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

func (g *threeParty) nextSeq() uint64 {
	g.seq++
	return g.seq
}

// bobRemovesCarol is the malicious Commit: Bob's client tells his Keeper a
// person asked for it, and the server accepts the Commit because it declares
// the member set unchanged.
func (g *threeParty) bobRemovesCarol(t *testing.T) proto.MLSCommitResponseData {
	t.Helper()
	b := g.bob.start("", 0)
	defer func() { b.in.Close(); <-b.done }()
	var built proto.MLSCommitResponseData
	b.must(proto.MLSCommitBuild, proto.MLSCommitBuildRequest{
		Permit: g.bob.permit(), OrgID: hOrg, ConversationID: hConv,
		ClientCommitID: g.bob.nextCommitID(), ExpectedEpoch: 1, RemoveAccountIDs: []string{hCarol},
		UserInitiated: true,
	}, &built)
	b.must(proto.MLSCommitConfirm, g.bob.confirmRequest(built.ClientCommitID), nil)
	return built
}

// blockDetail is the sync block a CHAT_MLS_ROW_REFUSED answer carries (N3).
func blockDetail(t *testing.T, r response) proto.MLSSyncBlock {
	t.Helper()
	if r.Success || r.ErrorCode != proto.ChatMLSErrorCodeRowRefused {
		t.Fatalf("response = %+v; want %s", r, proto.ChatMLSErrorCodeRowRefused)
	}
	var d proto.MLSSyncBlock
	if err := json.Unmarshal(r.Data, &d); err != nil {
		t.Fatalf("block detail: %v", err)
	}
	return d
}

func latchDetail(t *testing.T, r response) proto.ChatStateRekeyLatchedData {
	t.Helper()
	if r.Success || r.ErrorCode != proto.ChatStateErrorCodeRekeyRequired {
		t.Fatalf("response = %+v; want %s", r, proto.ChatStateErrorCodeRekeyRequired)
	}
	var d proto.ChatStateRekeyLatchedData
	if err := json.Unmarshal(r.Data, &d); err != nil {
		t.Fatalf("latch detail: %v", err)
	}
	return d
}

// Q4 and N3 through the binary: Alice refuses the same-set Remove under a
// genuine server signature and stops at its epoch (not a latch), and the
// block and its detail survive a forced kill. A tampered attestation is
// refused without recording anything.
func TestKeeperProcessRefusesAnUnauthorizedCommitAndTheBlockSurvivesAKill(t *testing.T) {
	g := newThreeParty(t)
	built := g.bobRemovesCarol(t)
	seq := g.nextSeq()

	a := g.alice.start("", 0)
	tampered := g.alice.attestedProcess(seq, 2, built.CommitB64, hAlice, hBob, hCarol)
	tampered.CommitAttestation = attestation(t, 3, built.CommitB64, hAlice, hBob, hCarol)
	a.refused(proto.MLSProcess, tampered, proto.ChatStateErrorCodeNotAuthorized)
	assertReady(t, a, 1)

	got := blockDetail(t, a.call(proto.MLSProcess, g.alice.attestedProcess(seq, 2, built.CommitB64, hAlice, hBob, hCarol)))
	if got.Cause != proto.ChatStateRekeyCauseUnauthorizedCommit || got.Epoch != 2 || got.CommitterAccountID != hBob {
		t.Fatalf("block detail = %+v", got)
	}
	a.killAndAssertKilled()

	a = g.alice.start("", 0)
	status := a.status()
	if status.NeedsRekey || status.SyncBlocked == nil || status.SyncBlocked.Epoch != 2 ||
		status.SyncBlocked.CommitterAccountID != hBob || status.SyncBlocked.CommitterDeviceID != hDevice || status.Epoch != 1 {
		t.Fatalf("status after the kill = %+v", status)
	}
	a.refused(proto.MLSEncrypt, g.alice.encryptRequest(messageID(1), 1, "never"), proto.ChatMLSErrorCodeSyncBlocked)
	// Where it is kept: the anchor's sync_block, nothing else of it moved.
	if anchor := g.alice.anchor(); anchor.NeedsRekey || anchor.RekeyCause != "" || anchor.SyncBlock == nil ||
		anchor.SyncBlock.Epoch != 2 || anchor.Epoch != 1 {
		t.Fatalf("anchor = %+v", anchor)
	}

	// Carol, the one removed, refuses her own unauthorized removal too.
	c := g.carol.start("", 0)
	if d := blockDetail(t, c.call(proto.MLSProcess, g.carol.attestedProcess(seq, 2, built.CommitB64, hAlice, hBob, hCarol))); d.Cause != proto.ChatStateRekeyCauseUnauthorizedCommit {
		t.Fatalf("carol's block = %+v", d)
	}
}

// Two Keeper processes of Alice's device handed the same unauthorized Commit
// at once: one writer at a time, both refuse, and the anchor holds one block
// with that detail and no latch.
func TestTwoKeeperProcessesRefuseTheSameUnauthorizedCommitOnce(t *testing.T) {
	g := newThreeParty(t)
	built := g.bobRemovesCarol(t)
	seq := g.nextSeq()
	p1, p2 := g.alice.start("", 0), g.alice.start("", 0)
	req := g.alice.attestedProcess(seq, 2, built.CommitB64, hAlice, hBob, hCarol)
	p1.send(proto.MLSProcess, req)
	p2.send(proto.MLSProcess, req)
	for _, p := range []*keeperProc{p1, p2} {
		r, err := p.receive()
		if err != nil {
			t.Fatalf("no answer: %v\n%s", err, p.stderr.String())
		}
		if r.Success || r.ErrorCode != proto.ChatMLSErrorCodeRowRefused {
			t.Fatalf("a process answered %+v", r)
		}
	}
	if anchor := g.alice.anchor(); anchor.NeedsRekey || anchor.SyncBlock == nil ||
		anchor.SyncBlock.CommitterAccountID != hBob || anchor.Epoch != 1 {
		t.Fatalf("anchor after two refusals = %+v", anchor)
	}
}

// Q16 through the binary: a replay of the Commit Bob applied is only already
// applied; another Commit served for that epoch latches fork, and the latch
// survives a SIGKILL.
func TestKeeperProcessLatchesAForkAndTheLatchSurvivesAKill(t *testing.T) {
	c := newConversation(t)
	a := c.alice.start("", 0)
	first := a.buildUpdate(c.alice.nextCommitID(), 1)
	a.must(proto.MLSCommitConfirm, c.alice.confirmRequest(first.ClientCommitID), nil)
	second := a.buildUpdate(c.alice.nextCommitID(), 2)

	b := c.bob.start("", 0)
	b.must(proto.MLSProcess, c.bob.attestedProcess(c.nextSeq(), 2, first.CommitB64, hAlice, hBob), nil)
	b.refused(proto.MLSProcess, c.bob.processRequest(c.nextSeq(), 2, first.CommitB64), proto.ChatMLSErrorCodeEpochStale)
	got := latchDetail(t, b.call(proto.MLSProcess, c.bob.attestedProcess(c.nextSeq(), 2, second.CommitB64, hAlice, hBob)))
	if got.RekeyCause != proto.ChatStateRekeyCauseFork || got.RekeyEpoch != 2 {
		t.Fatalf("fork detail = %+v", got)
	}
	b.killAndAssertKilled()

	b = c.bob.start("", 0)
	if status := b.status(); !status.NeedsRekey || status.RekeyCause != proto.ChatStateRekeyCauseFork || status.RekeyEpoch != 2 {
		t.Fatalf("status after the kill = %+v", status)
	}
}
