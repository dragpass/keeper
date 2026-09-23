// latch_test.go — where the S-1 latch lands in the record after each
// transaction. The real roster and the real pending Commit are exercised in
// internal/keystore/mls; this file pins what each transaction writes, which is
// the part a later refactor could quietly drop.

package chatstate

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
)

const (
	latchSelf    = "a1111111-1111-4111-8111-111111111111"
	latchRemoved = "b2222222-2222-4222-8222-222222222222"
)

func named(accounts ...string) ServerWatermark {
	return ServerWatermark{PendingRemovals: accounts}
}

func latchOf(t *testing.T, store *Store) []string {
	t.Helper()
	return readRecordForTest(t, store, testConvA).RemovalLatch
}

func latchSend(store *Store, wm ServerWatermark, cipher SendCipher) error {
	_, err := store.Send(testConvA, wm, SendRequest{ClientMessageID: "m-" + strings.Join(wm.PendingRemovals, ","), Plaintext: []byte("x")}, cipher)
	return err
}

// The refusal comes before burnUnfinished and the peek, and the list it was
// refused on is written down so the next permit cannot talk it away.
func TestSendRefusesBeforeTouchingTheRatchetAndRecordsTheLatch(t *testing.T) {
	store, _ := newTestStore(t)
	seedGroupState(t, store, testConvA, 1, 0, 3)
	cipher := &fakeCipher{roster: []string{latchSelf, latchRemoved}}

	if err := latchSend(store, named(latchRemoved), cipher); !errors.Is(err, ErrRotationPending) {
		t.Fatalf("send = %v; want ErrRotationPending", err)
	}
	if cipher.seals != 0 || cipher.burns != 0 || cipher.generation != 3 {
		t.Fatalf("a refused send moved the ratchet: seals %d burns %d generation %d",
			cipher.seals, cipher.burns, cipher.generation)
	}
	if got := latchOf(t, store); !slices.Equal(got, []string{latchRemoved}) {
		t.Fatalf("latch = %v", got)
	}
	if err := latchSend(store, noWatermark, cipher); !errors.Is(err, ErrRotationPending) {
		t.Fatalf("send under a permit that dropped the account = %v", err)
	}
}

// Nothing named and nothing latched is the ordinary conversation, and it
// never reads the roster.
func TestAConversationWithNothingNamedNeverReadsTheRoster(t *testing.T) {
	store, _ := newTestStore(t)
	seedGroupState(t, store, testConvA, 1, 0, 0)
	cipher := &fakeCipher{}
	if err := latchSend(store, noWatermark, cipher); err != nil {
		t.Fatal(err)
	}
	if cipher.rosterReads != 0 {
		t.Fatalf("the roster was read %d times", cipher.rosterReads)
	}
}

func TestAnAccountOutsideTheRosterIsNeverWrittenToTheLatch(t *testing.T) {
	store, _ := newTestStore(t)
	seedGroupState(t, store, testConvA, 1, 0, 0)
	if err := latchSend(store, named(latchRemoved), &fakeCipher{roster: []string{latchSelf}}); err != nil {
		t.Fatal(err)
	}
	if got := latchOf(t, store); got != nil {
		t.Fatalf("latch = %v", got)
	}
}

// BeginCommit keeps the latch (a built Remove is a fork), and ConfirmCommit is
// where the confirmed roster finally drops it.
func TestTheLatchSurvivesTheBuildAndGoesWithTheConfirmation(t *testing.T) {
	store, _ := newTestStore(t)
	seedGroupState(t, store, testConvA, 1, 0, 0)
	if err := latchSend(store, named(latchRemoved), &fakeCipher{roster: []string{latchSelf, latchRemoved}}); !errors.Is(err, ErrRotationPending) {
		t.Fatal(err)
	}

	committer := &fakeCommitter{roster: []string{latchSelf, latchRemoved}}
	begun, err := store.BeginCommit(testConvA, noWatermark, BeginCommitRequest{
		ClientCommitID: testCommitA,
		Plan:           CommitPlan{RemoveAccountIDs: []string{latchRemoved}},
	}, committer)
	if err != nil {
		t.Fatalf("a commit was refused while latched: %v", err)
	}
	if got := latchOf(t, store); !slices.Equal(got, []string{latchRemoved}) {
		t.Fatalf("latch after the build = %v", got)
	}

	committer.roster = []string{latchSelf}
	if _, err := store.ConfirmCommit(testConvA, named(latchRemoved), CommitOutcome{
		ClientCommitID: begun.ClientCommitID, Kind: CommitAccepted,
	}, committer); err != nil {
		t.Fatal(err)
	}
	if got := latchOf(t, store); got != nil {
		t.Fatalf("latch after the confirmed remove = %v", got)
	}
}

// Somebody else's Commit applied in Receive is confirmed on application, so it
// can release the latch there. A device that was itself removed keeps its
// latch: it has no roster left and nothing it could encrypt into.
func TestReceiveJudgesTheLatchOnTheStateItApplied(t *testing.T) {
	for name, tc := range map[string]struct {
		removed bool
		want    []string
	}{
		"a commit removing the member":  {false, nil},
		"a commit removing this device": {true, []string{latchRemoved}},
	} {
		t.Run(name, func(t *testing.T) {
			store, _ := newTestStore(t)
			seedGroupState(t, store, testConvA, 1, 0, 0)
			if err := latchSend(store, named(latchRemoved), &fakeCipher{roster: []string{latchSelf, latchRemoved}}); !errors.Is(err, ErrRotationPending) {
				t.Fatal(err)
			}
			in := &fakeInbound{opened: Opened{Epoch: 2, Removed: tc.removed}, roster: []string{latchSelf}}
			if _, err := store.Receive(testConvA, named(latchRemoved), ReceiveRequest{Seq: 1, Message: []byte("commit")}, in); err != nil {
				t.Fatal(err)
			}
			if got := latchOf(t, store); !slices.Equal(got, tc.want) {
				t.Fatalf("latch = %v; want %v", got, tc.want)
			}
		})
	}
}

// A record written before the field existed has no key for it, and a record
// with nothing latched writes none: both read as nothing latched.
func TestAnEmptyLatchIsAbsentFromTheRecord(t *testing.T) {
	body, err := json.Marshal(newRecord(latchSelf, testConvA))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "removal_latch") {
		t.Fatalf("an empty latch was written: %s", body)
	}
}
