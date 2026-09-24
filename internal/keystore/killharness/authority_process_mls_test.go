//go:build mls && cgo && (darwin || linux)

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

// Q4 through the binary: Alice refuses the same-set Remove under a genuine
// server signature, latches, and the latch and its detail survive a SIGKILL.
// A tampered attestation is refused without latching anything.
func TestKeeperProcessRefusesAnUnauthorizedCommitAndTheLatchSurvivesAKill(t *testing.T) {
	g := newThreeParty(t)
	built := g.bobRemovesCarol(t)
	seq := g.nextSeq()

	a := g.alice.start("", 0)
	tampered := g.alice.attestedProcess(seq, 2, built.CommitB64, hAlice, hBob, hCarol)
	tampered.CommitAttestation = attestation(t, 3, built.CommitB64, hAlice, hBob, hCarol)
	a.refused(proto.MLSProcess, tampered, proto.ChatStateErrorCodeNotAuthorized)
	assertReady(t, a, 1)

	got := latchDetail(t, a.call(proto.MLSProcess, g.alice.attestedProcess(seq, 2, built.CommitB64, hAlice, hBob, hCarol)))
	if got.RekeyCause != proto.ChatStateRekeyCauseUnauthorizedCommit || got.RekeyEpoch != 2 ||
		got.RekeyCommitterAccountID != hBob {
		t.Fatalf("latch detail = %+v", got)
	}
	a.killAndAssertKilled()

	a = g.alice.start("", 0)
	status := a.status()
	if !status.NeedsRekey || status.RekeyCause != proto.ChatStateRekeyCauseUnauthorizedCommit ||
		status.RekeyEpoch != 2 || status.RekeyCommitterAccountID != hBob || status.RekeyCommitterDeviceID != hDevice {
		t.Fatalf("status after the kill = %+v", status)
	}
	a.refused(proto.MLSEncrypt, g.alice.encryptRequest(messageID(1), 1, "never"), proto.ChatStateErrorCodeRekeyRequired)
	if anchor := g.alice.anchor(); anchor.RekeyCause != "unauthorized_commit" || anchor.RekeyEpoch != 2 {
		t.Fatalf("anchor = %+v", anchor)
	}

	// Carol, the one removed, refuses her own unauthorized removal too.
	c := g.carol.start("", 0)
	if d := latchDetail(t, c.call(proto.MLSProcess, g.carol.attestedProcess(seq, 2, built.CommitB64, hAlice, hBob, hCarol))); d.RekeyCause != proto.ChatStateRekeyCauseUnauthorizedCommit {
		t.Fatalf("carol's latch = %+v", d)
	}
}

// Two Keeper processes of Alice's device handed the same unauthorized Commit
// at once: one writer at a time, both refuse, and the anchor holds one latch
// with the first detail.
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
		if r.Success || r.ErrorCode != proto.ChatStateErrorCodeRekeyRequired {
			t.Fatalf("a process answered %+v", r)
		}
	}
	if anchor := g.alice.anchor(); !anchor.NeedsRekey || anchor.RekeyCause != "unauthorized_commit" ||
		anchor.RekeyCommitterAccountID != hBob {
		t.Fatalf("anchor after two refusals = %+v", anchor)
	}
}
