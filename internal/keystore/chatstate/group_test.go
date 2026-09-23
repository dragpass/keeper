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
