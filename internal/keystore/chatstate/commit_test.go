// commit_test.go — the pending / confirmed separation, driven through a
// stand-in for the MLS layer.
//
// The stand-in models the three library properties the design leans on and a
// naive fake would not have: a built Commit lands in a pending slot rather than
// in the confirmed state, a second build while one is pending is refused, and
// applying somebody else's Commit clears ours as part of the same step. Tests
// against the real library are in internal/keystore/mls.

package chatstate

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
)

const testCommitA = "77777777-7777-4777-8777-777777777777"
const testCommitB = "88888888-8888-4888-8888-888888888888"

// fakeCommitter keeps the confirmed position and the pending Commit in the same
// blob, which is what the chosen persistence form does: mls-rs puts a built
// Commit in Group.pending_commit and Snapshot carries that field through
// write_to_storage. A fake with a separate pending field would pass a test the
// real arrangement fails, because it would never show the two sharing a blob.
type fakeCommitter struct {
	epoch      uint64
	leaf       uint32
	generation uint64
	pending    uint64 // the epoch the pending Commit would produce; 0 = none
	loaded     bool

	builds   int
	applies  int
	clears   int
	appliedA []uint64 // the confirmed epoch each ApplyMessage ran against
	buildErr error
}

func fakePendingState(epoch uint64, leaf uint32, generation, pendingEpoch uint64) []byte {
	return fmt.Appendf(nil, "fake|%d|%d|%d|pending|%d", epoch, leaf, generation, pendingEpoch)
}

func (c *fakeCommitter) Load(blob []byte) error {
	fields := strings.Split(string(blob), "|")
	if len(fields) != 4 && len(fields) != 6 {
		return errors.New("fake committer: unusable state blob")
	}
	if fields[0] != "fake" {
		return errors.New("fake committer: unusable state blob")
	}
	epoch, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		return err
	}
	leaf, err := strconv.ParseUint(fields[2], 10, 32)
	if err != nil {
		return err
	}
	generation, err := strconv.ParseUint(fields[3], 10, 64)
	if err != nil {
		return err
	}
	c.pending = 0
	if len(fields) == 6 {
		if c.pending, err = strconv.ParseUint(fields[5], 10, 64); err != nil {
			return err
		}
	}
	c.epoch, c.leaf, c.generation, c.loaded = epoch, uint32(leaf), generation, true
	return nil
}

func (c *fakeCommitter) BuildCommit(plan CommitPlan) (BuiltCommit, error) {
	if !c.loaded {
		return BuiltCommit{}, errors.New("fake committer: built before loading")
	}
	if c.buildErr != nil {
		return BuiltCommit{}, c.buildErr
	}
	// mls-rs answers MlsError::ExistingPendingCommit here. The rule is the
	// library's, not the record's, and the fake carries it so a test cannot
	// pass by relying on the record check alone.
	if c.pending != 0 {
		return BuiltCommit{}, errors.New("fake committer: existing pending commit")
	}
	c.builds++
	c.pending = c.epoch + 1
	out := BuiltCommit{
		Commit:        fmt.Appendf(nil, "commit@%d", c.epoch),
		ExpectedEpoch: c.epoch,
	}
	if len(plan.AddKeyPackages) > 0 {
		out.Welcome = fmt.Appendf(nil, "welcome@%d", c.epoch+1)
	}
	return out, nil
}

func (c *fakeCommitter) ApplyPending() error {
	if c.pending == 0 {
		return errors.New("fake committer: no pending commit")
	}
	c.applies++
	c.epoch, c.pending, c.generation = c.pending, 0, 0
	return nil
}

func (c *fakeCommitter) ClearPending() error {
	c.clears++
	c.pending = 0
	return nil
}

// ApplyMessage records the confirmed epoch it ran against. That recording is
// the point of the fake: the CAS-loss assertion is "the winner was applied to
// the state that never moved", and only the epoch at the moment of the call
// can show it.
func (c *fakeCommitter) ApplyMessage(message []byte) (uint64, bool, error) {
	if !c.loaded {
		return 0, false, errors.New("fake committer: applied before loading")
	}
	built, err := strconv.ParseUint(strings.TrimPrefix(string(message), "commit@"), 10, 64)
	if err != nil {
		return 0, false, errors.New("fake committer: unrecognized commit")
	}
	if built != c.epoch {
		return 0, false, fmt.Errorf("fake committer: commit built at %d, group is at %d", built, c.epoch)
	}
	c.appliedA = append(c.appliedA, c.epoch)
	c.epoch, c.pending, c.generation = c.epoch+1, 0, 0
	return c.epoch, false, nil
}

func (c *fakeCommitter) Epoch() (uint64, error) {
	if !c.loaded {
		return 0, errors.New("fake committer: read before loading")
	}
	return c.epoch, nil
}

func (c *fakeCommitter) State() ([]byte, error) {
	if !c.loaded {
		return nil, errors.New("fake committer: serialized before loading")
	}
	if c.pending != 0 {
		return fakePendingState(c.epoch, c.leaf, c.generation, c.pending), nil
	}
	return fakeState(c.epoch, c.leaf, c.generation), nil
}

func beginForTest(t *testing.T, store *Store, clientCommitID string, cipher CommitCipher) BeginCommitResult {
	t.Helper()
	out, err := store.BeginCommit(testConvA, noWatermark, BeginCommitRequest{
		ClientCommitID: clientCommitID,
		Plan:           CommitPlan{AddKeyPackages: [][]byte{[]byte("a key package")}},
	}, cipher)
	if err != nil {
		t.Fatalf("begin commit: %v", err)
	}
	return out
}

func anchorForTest(t *testing.T, store *Store, conversationID string) Anchor {
	t.Helper()
	anchor, err := loadAnchor(store.secrets, store.conversationTag(conversationID))
	if err != nil {
		t.Fatalf("load anchor: %v", err)
	}
	return anchor
}

// ────────────────────────────────────────────────────────────────────────
// RFC 9420 §14: building a Commit must not modify the client's state.
// ────────────────────────────────────────────────────────────────────────

func TestBuildingACommitDoesNotMoveTheConfirmedState(t *testing.T) {
	store, _ := newTestStore(t)
	seedGroupState(t, store, testConvA, 4, 2, 7)
	before := readRecordForTest(t, store, testConvA)
	beforeAnchor := anchorForTest(t, store, testConvA)

	out := beginForTest(t, store, testCommitA, &fakeCommitter{})
	if out.ExpectedEpoch != 4 || !out.Created {
		t.Fatalf("begin = %+v, want expected epoch 4 and a fresh build", out)
	}

	after := readRecordForTest(t, store, testConvA)
	if after.Epoch != before.Epoch {
		t.Fatalf("the confirmed epoch moved from %d to %d while only building a commit",
			before.Epoch, after.Epoch)
	}
	if after.Pending == nil || after.Pending.ClientCommitID != testCommitA {
		t.Fatalf("the commit was not held pending: %+v", after.Pending)
	}
	// The send chain is untouched too. A Commit goes out as a PublicMessage
	// under encrypt_control_messages=false, so it consumes no generation on
	// either ratchet, and a lost race therefore costs no chain position.
	if want := string(fakePendingState(4, 2, 7, 5)); string(after.GroupState) != want {
		t.Fatalf("group state = %q, want %q", after.GroupState, want)
	}
	if after.NextIndex != before.NextIndex {
		t.Fatalf("the send chain moved from %d to %d", before.NextIndex, after.NextIndex)
	}

	afterAnchor := anchorForTest(t, store, testConvA)
	if afterAnchor.Epoch != beforeAnchor.Epoch {
		t.Fatalf("the anchor took the pending epoch: %d -> %d",
			beforeAnchor.Epoch, afterAnchor.Epoch)
	}
	if afterAnchor.ReservedBefore != beforeAnchor.ReservedBefore {
		t.Fatalf("the anchor's reservation ceiling moved: %d -> %d",
			beforeAnchor.ReservedBefore, afterAnchor.ReservedBefore)
	}
}

func TestASecondCommitIsRefusedWhileOneIsPending(t *testing.T) {
	store, _ := newTestStore(t)
	seedGroupState(t, store, testConvA, 0, 0, 0)
	cipher := &fakeCommitter{}
	beginForTest(t, store, testCommitA, cipher)

	_, err := store.BeginCommit(testConvA, noWatermark, BeginCommitRequest{
		ClientCommitID: testCommitB,
	}, cipher)
	if !errors.Is(err, ErrCommitPending) {
		t.Fatalf("second commit = %v, want ErrCommitPending", err)
	}
	if cipher.builds != 1 {
		t.Fatalf("the MLS layer built %d commits, want 1", cipher.builds)
	}
	if rec := readRecordForTest(t, store, testConvA); rec.Pending.ClientCommitID != testCommitA {
		t.Fatalf("the refused attempt replaced the pending: %+v", rec.Pending)
	}
}

// A lost response is retried with the same id, and a retry has to answer with
// the bytes already built. Building a second Commit for one attempt would put
// two forks on one epoch, which is the thing the single pending slot exists to
// make impossible.
func TestARetryUnderTheSameIdReturnsTheStoredCommit(t *testing.T) {
	store, _ := newTestStore(t)
	seedGroupState(t, store, testConvA, 0, 0, 0)
	cipher := &fakeCommitter{}
	first := beginForTest(t, store, testCommitA, cipher)
	generationAfterFirst := readRecordForTest(t, store, testConvA).Generation

	again := beginForTest(t, store, testCommitA, cipher)
	if again.Created {
		t.Fatal("the retry built a second commit")
	}
	if cipher.builds != 1 {
		t.Fatalf("the MLS layer built %d commits, want 1", cipher.builds)
	}
	if string(again.Commit) != string(first.Commit) || again.ExpectedEpoch != first.ExpectedEpoch {
		t.Fatalf("the retry answered with different bytes: %+v vs %+v", again, first)
	}
	if got := readRecordForTest(t, store, testConvA).Generation; got != generationAfterFirst {
		t.Fatalf("the retry wrote the record again (%d -> %d)", generationAfterFirst, got)
	}
}

// ────────────────────────────────────────────────────────────────────────
// The three outcomes (§7.3.2).
// ────────────────────────────────────────────────────────────────────────

func TestAnAcceptedCommitBecomesTheConfirmedState(t *testing.T) {
	store, _ := newTestStore(t)
	seedGroupState(t, store, testConvA, 4, 2, 7)
	cipher := &fakeCommitter{}
	begin := beginForTest(t, store, testCommitA, cipher)
	if begin.WelcomeReleasable {
		t.Fatal("the welcome was releasable before the commit was accepted")
	}

	out, err := store.ConfirmCommit(testConvA, noWatermark, CommitOutcome{
		ClientCommitID: testCommitA,
		Kind:           CommitAccepted,
	}, cipher)
	if err != nil {
		t.Fatalf("confirm: %v", err)
	}
	if out.Epoch != 5 {
		t.Fatalf("confirmed epoch = %d, want 5", out.Epoch)
	}
	if !out.WelcomeReleasable || string(out.Welcome) != "welcome@5" {
		t.Fatalf("the welcome was not released on acceptance: %+v", out)
	}
	if cipher.applies != 1 {
		t.Fatalf("the pending was applied %d times, want 1", cipher.applies)
	}

	rec := readRecordForTest(t, store, testConvA)
	if rec.Pending != nil {
		t.Fatalf("the pending outlived its acceptance: %+v", rec.Pending)
	}
	if rec.Epoch != 5 || string(rec.GroupState) != string(fakeState(5, 2, 0)) {
		t.Fatalf("record after acceptance: epoch %d state %q", rec.Epoch, rec.GroupState)
	}
	if anchor := anchorForTest(t, store, testConvA); anchor.Epoch != 5 {
		t.Fatalf("the anchor did not follow the confirmed epoch: %d", anchor.Epoch)
	}
}

// The CAS-loss path. Two assertions carry it: our fork is gone, and the
// winner's Commit was applied to the epoch we never left.
func TestALostRaceDropsThePendingAndAppliesTheWinnerFromThePreviousEpoch(t *testing.T) {
	store, _ := newTestStore(t)
	seedGroupState(t, store, testConvA, 4, 2, 7)
	cipher := &fakeCommitter{}
	beginForTest(t, store, testCommitA, cipher)

	out, err := store.ConfirmCommit(testConvA, noWatermark, CommitOutcome{
		ClientCommitID: testCommitA,
		Kind:           CommitSuperseded,
		WinnerMessage:  []byte("commit@4"),
	}, cipher)
	if err != nil {
		t.Fatalf("confirm superseded: %v", err)
	}
	if len(cipher.appliedA) != 1 || cipher.appliedA[0] != 4 {
		t.Fatalf("the winner was applied against epochs %v, want [4]", cipher.appliedA)
	}
	if cipher.applies != 0 {
		t.Fatal("the losing commit was promoted")
	}
	if cipher.clears == 0 {
		t.Fatal("the fork was not discarded")
	}
	if out.Epoch != 5 || out.WelcomeReleasable || out.Welcome != nil {
		t.Fatalf("superseded result = %+v; the welcome must not be released", out)
	}

	rec := readRecordForTest(t, store, testConvA)
	if rec.Pending != nil {
		t.Fatalf("the losing commit is still pending: %+v", rec.Pending)
	}
	if rec.Epoch != 5 || string(rec.GroupState) != string(fakeState(5, 2, 0)) {
		t.Fatalf("record after the loss: epoch %d state %q", rec.Epoch, rec.GroupState)
	}
	// The conversation is usable again immediately: losing a race is ordinary,
	// so nothing about it may latch.
	if _, err := store.BeginCommit(testConvA, noWatermark, BeginCommitRequest{
		ClientCommitID: testCommitB,
	}, cipher); err != nil {
		t.Fatalf("a retry after losing was refused: %v", err)
	}
}

// The third outcome is the absence of a verdict, and everything that would
// build on an epoch nobody has settled stops.
func TestAnUnsettledCommitStopsNewCommitsSendsAndTheWelcome(t *testing.T) {
	store, _ := newTestStore(t)
	seedGroupState(t, store, testConvA, 0, 0, 0)
	beginForTest(t, store, testCommitA, &fakeCommitter{})

	_, err := store.BeginCommit(testConvA, noWatermark,
		BeginCommitRequest{ClientCommitID: testCommitB}, &fakeCommitter{})
	if !errors.Is(err, ErrCommitPending) {
		t.Fatalf("new commit = %v, want ErrCommitPending", err)
	}

	sender := &fakeCipher{}
	_, err = store.Send(testConvA, noWatermark, SendRequest{
		ClientMessageID: testClientA,
		Plaintext:       []byte("not while the epoch is undecided"),
	}, sender)
	if !errors.Is(err, ErrCommitPending) {
		t.Fatalf("send = %v, want ErrCommitPending", err)
	}
	if sender.seals != 0 {
		t.Fatal("the AEAD ran under an undecided epoch")
	}

	_, err = store.Receive(testConvA, noWatermark,
		ReceiveRequest{Seq: 1, Message: []byte("wire")}, inbound(3, 0, "delivered"))
	if !errors.Is(err, ErrCommitPending) {
		t.Fatalf("receive = %v, want ErrCommitPending", err)
	}

	// What the caller may have is the Commit to repost and the id to ask the
	// server about. Not the Welcome: until the server accepts, there is no
	// epoch for a joiner to be welcomed into.
	pending, ok, err := store.PendingCommit(testConvA, noWatermark)
	if err != nil || !ok {
		t.Fatalf("pending commit = %v, %t", err, ok)
	}
	if pending.ClientCommitID != testCommitA || string(pending.Commit) != "commit@0" {
		t.Fatalf("pending = %+v", pending)
	}
	if pending.Welcome != nil {
		t.Fatalf("the welcome came back while the outcome was unknown: %q", pending.Welcome)
	}
}

// A retransmission is not a new send: it replays stored bytes and touches
// neither the ratchet nor the epoch, so the gate above must not catch it.
func TestARetransmissionStillWorksWhileACommitIsUnsettled(t *testing.T) {
	store, _ := newTestStore(t)
	seedGroupState(t, store, testConvA, 0, 0, 0)
	sender := &fakeCipher{}
	first, err := store.Send(testConvA, noWatermark, SendRequest{
		ClientMessageID: testClientA,
		Plaintext:       []byte("before the commit"),
	}, sender)
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	beginForTest(t, store, testCommitA, &fakeCommitter{})

	again, err := store.Send(testConvA, noWatermark, SendRequest{
		ClientMessageID: testClientA,
		Plaintext:       []byte("before the commit"),
	}, sender)
	if err != nil {
		t.Fatalf("retransmission during an unsettled commit: %v", err)
	}
	if again.Created || string(again.Entry.Ciphertext) != string(first.Entry.Ciphertext) {
		t.Fatalf("the retransmission did not replay the stored bytes: %+v", again)
	}
}

// A re-read comes out of the sealed local copy and never reaches MLS, so the
// receive gate must not close it. §13 keeps reading open when sending is shut.
func TestARereadStillWorksWhileACommitIsUnsettled(t *testing.T) {
	store, _ := newTestStore(t)
	seedGroupState(t, store, testConvA, 0, 0, 0)
	if _, err := store.Receive(testConvA, noWatermark,
		ReceiveRequest{Seq: 9, Message: []byte("wire")}, inbound(3, 0, "delivered")); err != nil {
		t.Fatalf("receive: %v", err)
	}
	beginForTest(t, store, testCommitA, &fakeCommitter{})

	plaintext, err := store.ReadHistory(testConvA, noWatermark, 9)
	if err != nil {
		t.Fatalf("reread during an unsettled commit: %v", err)
	}
	if string(plaintext) != "delivered" {
		t.Fatalf("reread returned %q", plaintext)
	}
}

func TestAVerdictForAnotherCommitIsRefused(t *testing.T) {
	store, _ := newTestStore(t)
	seedGroupState(t, store, testConvA, 0, 0, 0)
	cipher := &fakeCommitter{}

	_, err := store.ConfirmCommit(testConvA, noWatermark, CommitOutcome{
		ClientCommitID: testCommitA,
		Kind:           CommitAccepted,
	}, cipher)
	if !errors.Is(err, ErrNoPendingCommit) {
		t.Fatalf("confirm without a pending = %v, want ErrNoPendingCommit", err)
	}

	beginForTest(t, store, testCommitA, cipher)
	_, err = store.ConfirmCommit(testConvA, noWatermark, CommitOutcome{
		ClientCommitID: testCommitB,
		Kind:           CommitAccepted,
	}, cipher)
	if !errors.Is(err, ErrCommitMismatch) {
		t.Fatalf("confirm for another commit = %v, want ErrCommitMismatch", err)
	}
	if cipher.applies != 0 {
		t.Fatal("a verdict about another attempt promoted ours")
	}
}

func TestAPendingCommitSurvivesAFreshStore(t *testing.T) {
	store, secrets := newTestStore(t)
	seedGroupState(t, store, testConvA, 4, 2, 7)
	beginForTest(t, store, testCommitA, &fakeCommitter{})
	store.Close()

	reopened, err := Open(secrets, testOwner)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()

	pending, ok, err := reopened.PendingCommit(testConvA, noWatermark)
	if err != nil || !ok {
		t.Fatalf("pending commit after reopen = %v, %t", err, ok)
	}
	if pending.ClientCommitID != testCommitA || pending.ExpectedEpoch != 4 {
		t.Fatalf("pending after reopen = %+v", pending)
	}
	// The fork travels with it. A restart that found the record but not the
	// next-epoch state could not accept the commit it is still waiting on.
	cipher := &fakeCommitter{}
	out, err := reopened.ConfirmCommit(testConvA, noWatermark, CommitOutcome{
		ClientCommitID: testCommitA,
		Kind:           CommitAccepted,
	}, cipher)
	if err != nil {
		t.Fatalf("confirm after reopen: %v", err)
	}
	if out.Epoch != 5 {
		t.Fatalf("confirmed epoch after reopen = %d, want 5", out.Epoch)
	}
}

// ────────────────────────────────────────────────────────────────────────
// The anchor (§7.3.3): a pending Commit is an input to none of the three
// comparisons rewound() makes.
// ────────────────────────────────────────────────────────────────────────

func TestAPendingCommitIsNotAnInputToAnyRollbackComparison(t *testing.T) {
	anchor := Anchor{Generation: 5, ReservedBefore: 3, Epoch: 7}
	// A record holding a Commit that would reach epoch 8, and a server that
	// has seen nothing beyond epoch 7.
	base := func() *Record {
		return &Record{
			Generation: 5,
			NextIndex:  3,
			Epoch:      7,
			Pending:    &PendingCommit{ClientCommitID: testCommitA, ExpectedEpoch: 7},
		}
	}
	watermark := ServerWatermark{Epoch: 7, NextIndex: 3}

	if anchor.rewound(base(), watermark) {
		t.Fatal("a conversation with a pending commit read as rewound")
	}

	// Each comparison still bites on its own axis, which is what makes the
	// answer above a statement about the pending rather than about a check
	// that stopped working.
	for name, mutate := range map[string]func(*Record){
		"file generation": func(r *Record) { r.Generation = 4 },
		"chain position":  func(r *Record) { r.NextIndex = 4 },
		"confirmed epoch": func(r *Record) { r.Epoch = 6 },
	} {
		rec := base()
		mutate(rec)
		if !anchor.rewound(rec, watermark) {
			t.Fatalf("the %s comparison stopped catching a rewind", name)
		}
	}

	// And the server watermark axis: a server that has accepted something at
	// an epoch this record has not confirmed is a rewind, whether or not a
	// pending Commit would have reached that epoch.
	if !anchor.rewound(base(), ServerWatermark{Epoch: 8}) {
		t.Fatal("a server ahead of the confirmed epoch was not caught")
	}
}

// The concrete failure the rule above prevents: a device that wrote its
// pending epoch to the anchor would latch itself out of the conversation the
// first time it lost a race it is meant to lose sometimes.
func TestLosingARaceDoesNotLatchTheConversation(t *testing.T) {
	store, _ := newTestStore(t)
	seedGroupState(t, store, testConvA, 4, 2, 7)
	cipher := &fakeCommitter{}
	before := anchorForTest(t, store, testConvA).Epoch
	beginForTest(t, store, testCommitA, cipher)

	if got := anchorForTest(t, store, testConvA).Epoch; got != before {
		t.Fatalf("the anchor moved from %d to %d while the commit was pending", before, got)
	}
	if _, err := store.ConfirmCommit(testConvA, noWatermark, CommitOutcome{
		ClientCommitID: testCommitA,
		Kind:           CommitSuperseded,
		WinnerMessage:  []byte("commit@4"),
	}, cipher); err != nil {
		t.Fatalf("confirm superseded: %v", err)
	}
	if anchor := anchorForTest(t, store, testConvA); anchor.NeedsRekey {
		t.Fatal("losing a race latched the conversation")
	}
	if _, err := store.Send(testConvA, noWatermark, SendRequest{
		ClientMessageID: testClientA,
		Plaintext:       []byte("after the loss"),
	}, &fakeCipher{}); err != nil {
		t.Fatalf("send after losing a race: %v", err)
	}
}
