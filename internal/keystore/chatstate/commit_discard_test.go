// commit_discard_test.go — DiscardRefusedCommit: only the named pending
// Commit, on its own unmoved epoch, under the sign-in that built it.

package chatstate

import (
	"errors"
	"testing"
)

const (
	testLoginGeneration      = "login-generation-1"
	testOtherLoginGeneration = "login-generation-2"
)

func beginUnderLogin(t *testing.T, store *Store, clientCommitID, generation string, cipher CommitCipher) BeginCommitResult {
	t.Helper()
	out, err := store.BeginCommit(testConvA, noWatermark, BeginCommitRequest{
		ClientCommitID:  clientCommitID,
		Plan:            CommitPlan{AddKeyPackages: [][]byte{[]byte("a key package")}, UserInitiated: true},
		LoginGeneration: generation,
	}, cipher)
	if err != nil {
		t.Fatalf("begin commit: %v", err)
	}
	return out
}

func discardForTest(store *Store, clientCommitID string, epoch uint64, generation string, cipher CommitCipher) (DiscardResult, error) {
	return store.DiscardRefusedCommit(testConvA, noWatermark, RefusedCommitDiscard{
		ClientCommitID:  clientCommitID,
		ExpectedEpoch:   epoch,
		LoginGeneration: generation,
	}, cipher)
}

// requirePendingKept fails unless the record still holds Commit A at epoch 4,
// unchanged since generation `before`.
func requirePendingKept(t *testing.T, store *Store, before uint64) {
	t.Helper()
	rec := readRecordForTest(t, store, testConvA)
	if rec.Pending == nil || rec.Pending.ClientCommitID != testCommitA || rec.Pending.ExpectedEpoch != 4 {
		t.Fatalf("the refused discard touched the pending Commit: %+v", rec.Pending)
	}
	if rec.Generation != before {
		t.Fatalf("the refused discard wrote the record (%d -> %d)", before, rec.Generation)
	}
}

func TestARefusedCommitIsDiscardedAndTheConfirmedStateStays(t *testing.T) {
	store, _ := newTestStore(t)
	seedGroupState(t, store, testConvA, 4, 2, 7)
	cipher := &fakeCommitter{}
	beginUnderLogin(t, store, testCommitA, testLoginGeneration, cipher)
	built := readRecordForTest(t, store, testConvA)
	if built.Pending.LoginGeneration != testLoginGeneration {
		t.Fatalf("the build did not record its sign-in: %q", built.Pending.LoginGeneration)
	}
	beforeAnchor := anchorForTest(t, store, testConvA)

	out, err := discardForTest(store, testCommitA, 4, testLoginGeneration, cipher)
	if err != nil {
		t.Fatalf("discard: %v", err)
	}
	if !out.Discarded {
		t.Fatal("the refused Commit was not discarded")
	}
	rec := readRecordForTest(t, store, testConvA)
	if rec.Pending != nil {
		t.Fatalf("the pending Commit outlived its discard: %+v", rec.Pending)
	}
	if rec.Epoch != built.Epoch || string(rec.GroupState) != string(fakeState(4, 2, 7)) {
		t.Fatalf("the confirmed state moved: epoch %d state %q", rec.Epoch, rec.GroupState)
	}
	if out.Generation != rec.Generation {
		t.Fatalf("answered generation %d, record is at %d", out.Generation, rec.Generation)
	}
	if anchor := anchorForTest(t, store, testConvA); anchor.Epoch != beforeAnchor.Epoch {
		t.Fatalf("the anchor moved from %d to %d", beforeAnchor.Epoch, anchor.Epoch)
	}

	// The same intent rebuilds on the confirmed epoch under a new id.
	again := beginUnderLogin(t, store, testCommitB, testLoginGeneration, &fakeCommitter{})
	if !again.Created || again.ExpectedEpoch != 4 {
		t.Fatalf("rebuild after the discard = %+v, want a fresh build at epoch 4", again)
	}
}

func TestARefusedCommitDiscardMustNameThePendingCommitAndItsEpoch(t *testing.T) {
	cases := []struct {
		name  string
		id    string
		epoch uint64
	}{
		{"another commit id", testCommitB, 4},
		{"another epoch", testCommitA, 5},
		{"an earlier epoch", testCommitA, 3},
		{"the create epoch", testCommitA, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store, _ := newTestStore(t)
			seedGroupState(t, store, testConvA, 4, 2, 7)
			cipher := &fakeCommitter{}
			beginUnderLogin(t, store, testCommitA, testLoginGeneration, cipher)
			before := readRecordForTest(t, store, testConvA).Generation

			_, err := discardForTest(store, tc.id, tc.epoch, testLoginGeneration, cipher)
			if !errors.Is(err, ErrCommitMismatch) {
				t.Fatalf("discard = %v, want ErrCommitMismatch", err)
			}
			requirePendingKept(t, store, before)
		})
	}
}

// A discard decided before a sign-out and sign-in arrives late: the Commit was
// built under the earlier sign-in, so it is not this session's to drop.
func TestAStaleRefusedCommitDiscardAfterReLoginIsRefused(t *testing.T) {
	cases := []struct {
		name    string
		built   string
		request string
	}{
		{"built under the previous sign-in", testLoginGeneration, testOtherLoginGeneration},
		{"the request names no sign-in", testLoginGeneration, ""},
		{"built with no sign-in recorded", "", testLoginGeneration},
		{"neither names a sign-in", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store, _ := newTestStore(t)
			seedGroupState(t, store, testConvA, 4, 2, 7)
			cipher := &fakeCommitter{}
			beginUnderLogin(t, store, testCommitA, tc.built, cipher)
			before := readRecordForTest(t, store, testConvA).Generation

			_, err := discardForTest(store, testCommitA, 4, tc.request, cipher)
			if !errors.Is(err, ErrRefusedDiscardStale) {
				t.Fatalf("discard = %v, want ErrRefusedDiscardStale", err)
			}
			requirePendingKept(t, store, before)
			if cipher.clears != 0 {
				t.Fatalf("the MLS pending slot was cleared %d times", cipher.clears)
			}
		})
	}
}

// An accepted Commit is confirmed, so nothing is pending and a late discard
// of it is refused: it can never drop the epoch this device's Commit created.
func TestALateDiscardOfAnAcceptedCommitIsRefused(t *testing.T) {
	store, _ := newTestStore(t)
	seedGroupState(t, store, testConvA, 4, 2, 7)
	cipher := &fakeCommitter{}
	beginUnderLogin(t, store, testCommitA, testLoginGeneration, cipher)
	if _, err := store.ConfirmCommit(testConvA, noWatermark, CommitOutcome{
		ClientCommitID: testCommitA, Kind: CommitAccepted,
	}, cipher); err != nil {
		t.Fatalf("confirm: %v", err)
	}
	before := readRecordForTest(t, store, testConvA)

	_, err := discardForTest(store, testCommitA, 4, testLoginGeneration, cipher)
	if !errors.Is(err, ErrNoPendingCommit) {
		t.Fatalf("discard = %v, want ErrNoPendingCommit", err)
	}
	after := readRecordForTest(t, store, testConvA)
	if after.Epoch != before.Epoch || after.Generation != before.Generation ||
		string(after.GroupState) != string(before.GroupState) {
		t.Fatalf("the refused discard changed the accepted state: epoch %d gen %d -> %d",
			after.Epoch, before.Generation, after.Generation)
	}
}

// Another member's Commit took the epoch and was applied, and this device
// built a new Commit on the next one. A late discard of the first must not
// reach the second.
func TestALateDiscardAfterAnotherAcceptedCommitIsRefused(t *testing.T) {
	store, _ := newTestStore(t)
	seedGroupState(t, store, testConvA, 4, 2, 7)
	cipher := &fakeCommitter{}
	beginUnderLogin(t, store, testCommitA, testLoginGeneration, cipher)
	if _, err := store.ConfirmCommit(testConvA, noWatermark, CommitOutcome{
		ClientCommitID: testCommitA, Kind: CommitSuperseded, WinnerMessage: []byte("commit@4"),
	}, cipher); err != nil {
		t.Fatalf("confirm superseded: %v", err)
	}

	if _, err := discardForTest(store, testCommitA, 4, testLoginGeneration, cipher); !errors.Is(err, ErrNoPendingCommit) {
		t.Fatalf("discard with nothing pending = %v, want ErrNoPendingCommit", err)
	}

	beginUnderLogin(t, store, testCommitB, testLoginGeneration, cipher)
	before := readRecordForTest(t, store, testConvA)
	if _, err := discardForTest(store, testCommitA, 4, testLoginGeneration, cipher); !errors.Is(err, ErrCommitMismatch) {
		t.Fatalf("discard of the earlier Commit = %v, want ErrCommitMismatch", err)
	}
	after := readRecordForTest(t, store, testConvA)
	if after.Pending == nil || after.Pending.ClientCommitID != testCommitB || after.Pending.ExpectedEpoch != 5 ||
		after.Generation != before.Generation {
		t.Fatalf("the late discard reached the newer Commit: %+v", after.Pending)
	}
}

// A retried build answers from the stored Commit and keeps the sign-in it was
// first built under.
func TestARetriedBuildKeepsTheFirstSignIn(t *testing.T) {
	store, _ := newTestStore(t)
	seedGroupState(t, store, testConvA, 4, 2, 7)
	cipher := &fakeCommitter{}
	beginUnderLogin(t, store, testCommitA, testLoginGeneration, cipher)
	beginUnderLogin(t, store, testCommitA, testOtherLoginGeneration, cipher)
	if got := readRecordForTest(t, store, testConvA).Pending.LoginGeneration; got != testLoginGeneration {
		t.Fatalf("the retry replaced the sign-in with %q", got)
	}
	if _, err := discardForTest(store, testCommitA, 4, testOtherLoginGeneration, cipher); !errors.Is(err, ErrRefusedDiscardStale) {
		t.Fatalf("discard under the retry's sign-in = %v, want ErrRefusedDiscardStale", err)
	}
}

// shiftedEpochCommitter reports a confirmed epoch other than the one the
// pending Commit was built on, as a group state another Commit moved would.
type shiftedEpochCommitter struct{ fakeCommitter }

func (c *shiftedEpochCommitter) Epoch() (uint64, error) {
	epoch, err := c.fakeCommitter.Epoch()
	return epoch + 1, err
}

func TestARefusedCommitDiscardOnAMovedGroupEpochIsRefused(t *testing.T) {
	store, _ := newTestStore(t)
	seedGroupState(t, store, testConvA, 4, 2, 7)
	beginUnderLogin(t, store, testCommitA, testLoginGeneration, &fakeCommitter{})
	before := readRecordForTest(t, store, testConvA).Generation

	cipher := &shiftedEpochCommitter{}
	if _, err := discardForTest(store, testCommitA, 4, testLoginGeneration, cipher); !errors.Is(err, ErrCommitMismatch) {
		t.Fatalf("discard = %v, want ErrCommitMismatch", err)
	}
	requirePendingKept(t, store, before)
	if cipher.clears != 0 {
		t.Fatalf("the MLS pending slot was cleared %d times", cipher.clears)
	}
}

// A pending create is dropped by DiscardUnacceptedGroup, together with the
// group it made, never by this.
func TestARefusedCommitDiscardNeverDropsAPendingCreate(t *testing.T) {
	store, _ := newTestStore(t)
	seedGroupState(t, store, testConvA, 0, 0, 0)
	cipher := &fakeCommitter{}
	beginUnderLogin(t, store, testCommitA, testLoginGeneration, cipher)
	before := readRecordForTest(t, store, testConvA)
	if before.Pending == nil || before.Pending.ExpectedEpoch != 0 {
		t.Fatalf("setup: pending = %+v, want a create at epoch 0", before.Pending)
	}

	if _, err := discardForTest(store, testCommitA, 0, testLoginGeneration, cipher); !errors.Is(err, ErrCommitMismatch) {
		t.Fatalf("discard of a create = %v, want ErrCommitMismatch", err)
	}
	if after := readRecordForTest(t, store, testConvA); after.Pending == nil || after.Generation != before.Generation {
		t.Fatalf("the refused discard touched the create: %+v", after.Pending)
	}
}
