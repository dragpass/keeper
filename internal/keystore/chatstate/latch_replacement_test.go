// latch_replacement_test.go — where the M4.4 leaf-replacement latch lands in
// the record after each transaction. The real roster, the real replace Commit
// and three Keepers are exercised in internal/keystore/dispatch.

package chatstate

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

var (
	oldFP = strings.Repeat("0", 64)
	newFP = strings.Repeat("1", 64)
)

func takeover() LeafReplacement {
	return LeafReplacement{AccountID: latchRemoved, NewFingerprint: newFP}
}

func replacing(entries ...LeafReplacement) ServerWatermark {
	return ServerWatermark{PendingLeafReplacements: entries}
}

func leavesOf(fps ...string) []RosterLeaf {
	out := []RosterLeaf{{AccountID: latchSelf, Fingerprint: strings.Repeat("9", 64)}}
	for _, fp := range fps {
		out = append(out, RosterLeaf{AccountID: latchRemoved, Fingerprint: fp})
	}
	return out
}

func replacementLatchOf(t *testing.T, store *Store) []LeafReplacement {
	t.Helper()
	return readRecordForTest(t, store, testConvA).LeafReplacementLatch
}

func replacementSend(store *Store, wm ServerWatermark, cipher SendCipher) error {
	sendSeq++
	_, err := store.Send(testConvA, wm, SendRequest{
		ClientMessageID: "r-" + strings.Repeat("x", sendSeq), Plaintext: []byte("x"),
	}, cipher)
	return err
}

var sendSeq int

// The refusal is its own error, comes before burnUnfinished and the peek, and
// the entry is written down so the next permit cannot talk it away.
func TestAReplacementLatchRefusesSendBeforeTheRatchetAndOutlivesThePermit(t *testing.T) {
	store, _ := newTestStore(t)
	seedGroupState(t, store, testConvA, 1, 0, 3)
	cipher := &fakeCipher{leaves: leavesOf(oldFP)}

	if err := replacementSend(store, replacing(takeover()), cipher); !errors.Is(err, ErrLeafReplacementPending) {
		t.Fatalf("send = %v; want ErrLeafReplacementPending", err)
	}
	if cipher.seals != 0 || cipher.burns != 0 || cipher.generation != 3 {
		t.Fatalf("a refused send moved the ratchet: seals %d burns %d generation %d",
			cipher.seals, cipher.burns, cipher.generation)
	}
	if got := replacementLatchOf(t, store); !slices.Equal(got, []LeafReplacement{takeover()}) {
		t.Fatalf("latch = %v", got)
	}
	if err := replacementSend(store, noWatermark, cipher); !errors.Is(err, ErrLeafReplacementPending) {
		t.Fatalf("send under a permit that dropped the entry = %v", err)
	}

	// A restart is a new Store over the same files.
	reopened, err := Open(store.secrets, testOwner)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if err := replacementSend(reopened, noWatermark, cipher); !errors.Is(err, ErrLeafReplacementPending) {
		t.Fatalf("send after a restart = %v", err)
	}
}

// The latch lifts on the confirmed roster alone: every leaf of the account on
// the named key, or no leaf of the account left. Anything else keeps it.
func TestAReplacementLatchLiftsOnlyOnTheConfirmedRoster(t *testing.T) {
	for name, tc := range map[string]struct {
		leaves []RosterLeaf
		lifts  bool
	}{
		"only the new key":           {leavesOf(newFP), true},
		"no leaf of the account":     {leavesOf(), true},
		"old key still there":        {leavesOf(oldFP), false},
		"old and new side by side":   {leavesOf(oldFP, newFP), false},
		"a third key, not the named": {leavesOf(strings.Repeat("2", 64)), false},
	} {
		t.Run(name, func(t *testing.T) {
			store, _ := newTestStore(t)
			seedGroupState(t, store, testConvA, 1, 0, 0)
			if err := replacementSend(store, replacing(takeover()), &fakeCipher{leaves: leavesOf(oldFP)}); !errors.Is(err, ErrLeafReplacementPending) {
				t.Fatal(err)
			}
			err := replacementSend(store, noWatermark, &fakeCipher{leaves: tc.leaves})
			if tc.lifts {
				if err != nil {
					t.Fatalf("send = %v; want the latch lifted", err)
				}
				if got := replacementLatchOf(t, store); got != nil {
					t.Fatalf("latch after lifting = %v", got)
				}
				return
			}
			if !errors.Is(err, ErrLeafReplacementPending) {
				t.Fatalf("send = %v; want ErrLeafReplacementPending", err)
			}
		})
	}
}

// A permit naming a key the confirmed roster already holds as the account's
// only leaf, or an account the roster does not hold, latches nothing.
func TestAReplacementAlreadyInPlaceIsNotLatched(t *testing.T) {
	store, _ := newTestStore(t)
	seedGroupState(t, store, testConvA, 1, 0, 0)
	if err := replacementSend(store, replacing(takeover()), &fakeCipher{leaves: leavesOf(newFP)}); err != nil {
		t.Fatal(err)
	}
	if err := replacementSend(store, replacing(takeover()), &fakeCipher{leaves: leavesOf()}); err != nil {
		t.Fatal(err)
	}
	if got := replacementLatchOf(t, store); got != nil {
		t.Fatalf("latch = %v", got)
	}
}

// Both latches held: the removal is what the send reports, and both are kept.
func TestBothLatchesHeldReportTheRemoval(t *testing.T) {
	store, _ := newTestStore(t)
	seedGroupState(t, store, testConvA, 1, 0, 0)
	wm := ServerWatermark{PendingRemovals: []string{latchRemoved}, PendingLeafReplacements: []LeafReplacement{takeover()}}
	cipher := &fakeCipher{roster: []string{latchSelf, latchRemoved}, leaves: leavesOf(oldFP)}
	if err := replacementSend(store, wm, cipher); !errors.Is(err, ErrRotationPending) {
		t.Fatalf("send = %v; want ErrRotationPending", err)
	}
	rec := readRecordForTest(t, store, testConvA)
	if !slices.Equal(rec.RemovalLatch, []string{latchRemoved}) ||
		!slices.Equal(rec.LeafReplacementLatch, []LeafReplacement{takeover()}) {
		t.Fatalf("latches = %v, %v", rec.RemovalLatch, rec.LeafReplacementLatch)
	}
}

// BeginCommit is never refused and keeps the latch (a built replace is a
// fork); ConfirmCommit is where the confirmed roster finally drops it.
func TestAReplacementLatchSurvivesTheBuildAndGoesWithTheConfirmation(t *testing.T) {
	store, _ := newTestStore(t)
	seedGroupState(t, store, testConvA, 1, 0, 0)
	committer := &fakeCommitter{leaves: leavesOf(oldFP)}
	begun, err := store.BeginCommit(testConvA, replacing(takeover()), BeginCommitRequest{
		ClientCommitID: testCommitA,
		Plan: CommitPlan{Replace: []ReplaceMember{
			{AccountID: latchRemoved, NewFingerprint: newFP, KeyPackage: []byte("kp")},
		}},
	}, committer)
	if err != nil {
		t.Fatalf("a replace commit was refused while latched: %v", err)
	}
	if got := replacementLatchOf(t, store); !slices.Equal(got, []LeafReplacement{takeover()}) {
		t.Fatalf("latch after the build = %v", got)
	}

	committer.leaves = leavesOf(newFP)
	if _, err := store.ConfirmCommit(testConvA, noWatermark, CommitOutcome{
		ClientCommitID: begun.ClientCommitID, Kind: CommitAccepted,
	}, committer); err != nil {
		t.Fatal(err)
	}
	if got := replacementLatchOf(t, store); got != nil {
		t.Fatalf("latch after the confirmed replace = %v", got)
	}
}

// A replace entry the permit does not list, or lists under another key, is
// refused before anything is loaded or built.
func TestAReplaceThePermitDoesNotListBuildsNothing(t *testing.T) {
	for name, wm := range map[string]ServerWatermark{
		"account not listed": noWatermark,
		"another key listed": replacing(LeafReplacement{AccountID: latchRemoved, NewFingerprint: oldFP}),
	} {
		t.Run(name, func(t *testing.T) {
			store, _ := newTestStore(t)
			seedGroupState(t, store, testConvA, 1, 0, 0)
			before := readRecordForTest(t, store, testConvA).Generation
			committer := &fakeCommitter{leaves: leavesOf(oldFP)}
			_, err := store.BeginCommit(testConvA, wm, BeginCommitRequest{
				ClientCommitID: testCommitA,
				Plan: CommitPlan{Replace: []ReplaceMember{
					{AccountID: latchRemoved, NewFingerprint: newFP, KeyPackage: []byte("kp")},
				}},
			}, committer)
			if !errors.Is(err, ErrReplacementNotListed) {
				t.Fatalf("begin = %v; want ErrReplacementNotListed", err)
			}
			if committer.builds != 0 {
				t.Fatal("a refused replace reached the build")
			}
			if rec := readRecordForTest(t, store, testConvA); rec.Pending != nil || rec.Generation != before {
				t.Fatal("a refused replace wrote the record")
			}
		})
	}
}

// Receive judges on the state Open left behind; a device the Commit removed
// keeps what it had.
func TestReceiveJudgesTheReplacementLatchOnTheStateItApplied(t *testing.T) {
	for name, tc := range map[string]struct {
		removed bool
		want    []LeafReplacement
	}{
		"a commit replacing the leaf":   {false, nil},
		"a commit removing this device": {true, []LeafReplacement{takeover()}},
	} {
		t.Run(name, func(t *testing.T) {
			store, _ := newTestStore(t)
			seedGroupState(t, store, testConvA, 1, 0, 0)
			if err := replacementSend(store, replacing(takeover()), &fakeCipher{leaves: leavesOf(oldFP)}); !errors.Is(err, ErrLeafReplacementPending) {
				t.Fatal(err)
			}
			in := &fakeInbound{opened: Opened{Epoch: 2, Removed: tc.removed}, leaves: leavesOf(newFP)}
			if _, err := store.Receive(testConvA, noWatermark, ReceiveRequest{Seq: 1, Message: []byte("commit")}, in); err != nil {
				t.Fatal(err)
			}
			if got := replacementLatchOf(t, store); !slices.Equal(got, tc.want) {
				t.Fatalf("latch = %v; want %v", got, tc.want)
			}
		})
	}
}

// Status reports the latch the next send would be judged against, and writes
// nothing.
func TestStatusReportsTheReplacementLatch(t *testing.T) {
	store, _ := newTestStore(t)
	seedGroupState(t, store, testConvA, 1, 0, 0)
	before := readRecordForTest(t, store, testConvA).Generation
	status, err := store.Status(testConvA, replacing(takeover()), &fakeCipher{leaves: leavesOf(oldFP)})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(status.LeafReplacementLatch, []LeafReplacement{takeover()}) {
		t.Fatalf("status latch = %v", status.LeafReplacementLatch)
	}
	if readRecordForTest(t, store, testConvA).Generation != before {
		t.Fatal("status wrote the record")
	}
}
