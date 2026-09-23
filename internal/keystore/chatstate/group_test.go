package chatstate

import (
	"errors"
	"testing"
)

// A joined group records the epoch it joined at, so the handshake ordering
// rule and the anchor are judged against the real confirmed epoch.
func TestAJoinRecordsItsEpoch(t *testing.T) {
	store, _ := newTestStore(t)
	if _, err := store.SaveJoinedGroupState(testConvA, noWatermark, fakeState(4, 1, 0), 4); err != nil {
		t.Fatal(err)
	}
	if rec := readRecordForTest(t, store, testConvA); rec.Epoch != 4 {
		t.Fatalf("joined record is at epoch %d, want 4", rec.Epoch)
	}
}

// A handshake is applied only when it produces the epoch after the confirmed
// one. Both refusals come before the MLS layer is touched and write nothing.
func TestAHandshakeOutOfEpochOrderIsRefusedBeforeMLS(t *testing.T) {
	store, _ := newTestStore(t)
	if _, err := store.SaveJoinedGroupState(testConvA, noWatermark, fakeState(3, 1, 0), 3); err != nil {
		t.Fatal(err)
	}
	before := readRecordForTest(t, store, testConvA).Generation
	for produced, want := range map[uint64]error{3: ErrHandshakeApplied, 2: ErrHandshakeApplied, 5: ErrHandshakeSkipped} {
		cipher := &fakeInbound{opened: Opened{Epoch: produced}}
		_, err := store.Receive(testConvA, noWatermark,
			ReceiveRequest{Seq: 9, Message: []byte("commit"), Handshake: true, ProducedEpoch: produced}, cipher)
		if !errors.Is(err, want) {
			t.Fatalf("produced %d: %v, want %v", produced, err, want)
		}
		if cipher.opens != 0 || cipher.loaded {
			t.Fatalf("produced %d reached the MLS layer", produced)
		}
	}
	if readRecordForTest(t, store, testConvA).Generation != before {
		t.Fatal("a refused handshake wrote to the record")
	}

	// The next epoch applies; an application message handed in as one does not.
	app := inbound(0, 0, "hello")
	app.opened.Epoch = 4
	if _, err := store.Receive(testConvA, noWatermark,
		ReceiveRequest{Seq: 9, Message: []byte("m"), Handshake: true, ProducedEpoch: 4}, app); !errors.Is(err, ErrNotHandshake) {
		t.Fatalf("application as handshake = %v", err)
	}
	if _, err := store.Receive(testConvA, noWatermark,
		ReceiveRequest{Seq: 9, Message: []byte("c"), Handshake: true, ProducedEpoch: 4},
		&fakeInbound{opened: Opened{Epoch: 4}}); err != nil {
		t.Fatalf("the next handshake: %v", err)
	}
	if rec := readRecordForTest(t, store, testConvA); rec.Epoch != 4 {
		t.Fatalf("epoch %d after the handshake, want 4", rec.Epoch)
	}
}

// A join over a pending Commit is refused: the record would say a Commit is
// waiting on a group it no longer holds.
func TestAJoinOverAPendingCommitIsRefused(t *testing.T) {
	store, _ := newTestStore(t)
	seedGroupState(t, store, testConvA, 1, 0, 0)
	cipher := &fakeCommitter{}
	if _, err := store.BeginCommit(testConvA, noWatermark,
		BeginCommitRequest{ClientCommitID: "c1"}, cipher); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SaveJoinedGroupState(testConvA, noWatermark, fakeState(2, 1, 0), 2); !errors.Is(err, ErrCommitPending) {
		t.Fatalf("join over a pending commit = %v", err)
	}
}

// fakeCreator is fakeCommitter with the one call that makes a group at
// epoch 0 out of nothing.
type fakeCreator struct{ fakeCommitter }

func (c *fakeCreator) CreateGroup([]byte) error {
	c.epoch, c.leaf, c.generation, c.pending, c.loaded = 0, 0, 0, 0, true
	return nil
}

func createForTest(t *testing.T, store *Store, clientCommitID string) {
	t.Helper()
	if _, err := store.CreateGroup(testConvA, noWatermark, BeginCommitRequest{
		ClientCommitID: clientCommitID,
		Plan:           CommitPlan{AddKeyPackages: [][]byte{[]byte("a key package")}},
	}, &fakeCreator{}); err != nil {
		t.Fatalf("create group: %v", err)
	}
}

// The DM race's loser: its create is dropped, a second call finds nothing to
// drop, and the winner's group can then be joined.
func TestAnUnacceptedCreateIsDiscardedAndTheWinnerJoined(t *testing.T) {
	store, _ := newTestStore(t)
	createForTest(t, store, testCommitA)

	got, err := store.DiscardUnacceptedGroup(testConvA, noWatermark, testCommitA)
	if err != nil || !got.Discarded {
		t.Fatalf("discard = %+v, %v", got, err)
	}
	rec := readRecordForTest(t, store, testConvA)
	if len(rec.GroupState) != 0 || rec.Pending != nil || rec.Epoch != 0 || rec.Generation != got.Generation {
		t.Fatalf("record after the discard = %+v", rec)
	}
	again, err := store.DiscardUnacceptedGroup(testConvA, noWatermark, testCommitA)
	if err != nil || again.Discarded || again.Generation != got.Generation {
		t.Fatalf("discard again = %+v, %v; want nothing written", again, err)
	}
	if _, err := store.SaveJoinedGroupState(testConvA, noWatermark, fakeState(1, 1, 0), 1); err != nil {
		t.Fatalf("join after the discard: %v", err)
	}
	// A conversation that never had anything is the same no-op.
	if none, err := store.DiscardUnacceptedGroup(testConvB, noWatermark, testCommitA); err != nil || none.Discarded {
		t.Fatalf("discard of an empty conversation = %+v, %v", none, err)
	}
}

// Every state that is not this device's unaccepted create is refused, and a
// refusal writes nothing.
func TestADiscardIsRefusedForAnyOtherState(t *testing.T) {
	refuse := func(t *testing.T, store *Store, id string, want error) {
		t.Helper()
		before := readRecordForTest(t, store, testConvA)
		if _, err := store.DiscardUnacceptedGroup(testConvA, noWatermark, id); !errors.Is(err, want) {
			t.Fatalf("discard = %v, want %v", err, want)
		}
		after := readRecordForTest(t, store, testConvA)
		if after.Generation != before.Generation || len(after.GroupState) == 0 {
			t.Fatal("a refused discard wrote the record")
		}
	}

	t.Run("another commit id", func(t *testing.T) {
		store, _ := newTestStore(t)
		createForTest(t, store, testCommitA)
		refuse(t, store, testCommitB, ErrCommitMismatch)
	})
	t.Run("an accepted create", func(t *testing.T) {
		store, _ := newTestStore(t)
		createForTest(t, store, testCommitA)
		if _, err := store.ConfirmCommit(testConvA, noWatermark,
			CommitOutcome{ClientCommitID: testCommitA, Kind: CommitAccepted}, &fakeCommitter{}); err != nil {
			t.Fatal(err)
		}
		refuse(t, store, testCommitA, ErrNotUnacceptedCreate)
	})
	t.Run("a pending commit that is not a create", func(t *testing.T) {
		store, _ := newTestStore(t)
		seedGroupState(t, store, testConvA, 1, 0, 0)
		beginForTest(t, store, testCommitA, &fakeCommitter{})
		refuse(t, store, testCommitA, ErrNotUnacceptedCreate)
	})
	t.Run("a joined group", func(t *testing.T) {
		store, _ := newTestStore(t)
		if _, err := store.SaveJoinedGroupState(testConvA, noWatermark, fakeState(3, 1, 0), 3); err != nil {
			t.Fatal(err)
		}
		refuse(t, store, testCommitA, ErrNotUnacceptedCreate)
	})
}
