package chatstate

import (
	"errors"
	"os"
	"testing"
)

func assertLatched(t *testing.T, store *Store, conversationID string, want RekeyCause) {
	t.Helper()
	anchor := anchorForTest(t, store, conversationID)
	if !anchor.NeedsRekey || anchor.RekeyCause != want {
		t.Fatalf("anchor = needs_rekey %v, cause %q; want latched for %q", anchor.NeedsRekey, anchor.RekeyCause, want)
	}
}

// A join at epoch 4 as leaf 2 records where this device's chain starts, and a
// watermark that is some other chain — another leaf, or this index before this
// device held it — neither latches the join nor lands in the anchor.
func TestAJoinIgnoresAWatermarkThatIsNotItsChain(t *testing.T) {
	for name, wm := range map[string]ServerWatermark{
		"another leaf, an earlier epoch":        {Epoch: 3, LeafIndex: 1, NextApplicationIndex: 5},
		"another leaf, the join epoch":          {Epoch: 4, LeafIndex: 1, NextApplicationIndex: 5},
		"another leaf, a later epoch":           {Epoch: 6, LeafIndex: 1, NextApplicationIndex: 5},
		"this index before this device held it": {Epoch: 3, LeafIndex: 2, NextApplicationIndex: 5},
	} {
		t.Run(name, func(t *testing.T) {
			store, _ := newTestStore(t)
			if _, err := store.SaveJoinedGroupState(testConvA, wm, fakeState(4, 2, 0), 4, 2, nil); err != nil {
				t.Fatalf("join = %v", err)
			}
			rec := readRecordForTest(t, store, testConvA)
			if rec.OwnLeaf == nil || *rec.OwnLeaf != (OwnLeaf{Index: 2, SinceEpoch: 4}) || rec.Epoch != 4 {
				t.Fatalf("joined record = epoch %d, own leaf %+v", rec.Epoch, rec.OwnLeaf)
			}
			anchor := anchorForTest(t, store, testConvA)
			if anchor.NeedsRekey || anchor.hasWatermark() || anchor.WatermarkEpoch != 0 {
				t.Fatalf("another chain's watermark reached the anchor: %+v", anchor)
			}
			// The same permit keeps working after the join.
			if _, err := store.Send(testConvA, wm, SendRequest{
				ClientMessageID: testClientA, Plaintext: []byte("hello"),
			}, &fakeCipher{}); err != nil {
				t.Fatalf("send under the same permit = %v", err)
			}
		})
	}
}

// A replayed Welcome, into a fresh record, while the server holds a newer
// position of the same leaf from the join epoch on: that chain is this
// device's, so the join is judged against it once it has entered, and latches.
func TestAReplayedWelcomeUnderANewerWatermarkForTheSameLeafLatches(t *testing.T) {
	for name, wm := range map[string]ServerWatermark{
		"a later epoch":  {Epoch: 6, LeafIndex: 3, NextApplicationIndex: 2},
		"the join epoch": {Epoch: 5, LeafIndex: 3, NextApplicationIndex: 4},
	} {
		t.Run(name, func(t *testing.T) {
			store, _ := newTestStore(t)
			if _, err := store.SaveJoinedGroupState(testConvA, wm, fakeState(5, 3, 0), 5, 3, nil); !errors.Is(err, ErrRekeyRequired) {
				t.Fatalf("replayed join = %v, want ErrRekeyRequired", err)
			}
			assertLatched(t, store, testConvA, RekeyCauseWatermarkAhead)
			if rec, err := store.readRecord(store.paths(testConvA), testConvA); err != nil || rec != nil {
				t.Fatalf("the refused join wrote a record: %+v, %v", rec, err)
			}
		})
	}
}

// The local half is judged on the record the anchor describes, before the
// join touches it. A file restored under a live anchor is refused, and so is
// every later attempt: nothing lifts the latch, including a clean permit.
func TestAJoinOverARestoredFileUnderALiveAnchorLatches(t *testing.T) {
	store, _ := newTestStore(t)
	seedGroupState(t, store, testConvA, 0, 0, 0)
	path := store.paths(testConvA).record
	snapshot, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	seedGroupState(t, store, testConvA, 0, 0, 1)
	seedGroupState(t, store, testConvA, 0, 0, 2)
	if err := os.WriteFile(path, snapshot, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := store.SaveJoinedGroupState(testConvA, noWatermark, fakeState(3, 1, 0), 3, 1, nil); !errors.Is(err, ErrRekeyRequired) {
		t.Fatalf("join over a restored file = %v, want ErrRekeyRequired", err)
	}
	assertLatched(t, store, testConvA, RekeyCauseRollback)
	if _, err := store.SaveJoinedGroupState(testConvA, noWatermark, fakeState(3, 1, 0), 3, 1, nil); !errors.Is(err, ErrRekeyRequired) {
		t.Fatalf("second join = %v, want ErrRekeyRequired", err)
	}
	status, err := store.Status(testConvA, noWatermark, &fakeInbound{})
	if err != nil || !status.NeedsRekey || status.RekeyCause != RekeyCauseRollback {
		t.Fatalf("status = %+v, %v", status, err)
	}
}

// A missing file under an anchor that has authorized anything is a deletion,
// and a join does not make it a first use.
func TestAJoinWithTheFileMissingUnderANonZeroAnchorLatches(t *testing.T) {
	store, _ := newTestStore(t)
	if _, err := store.Reserve(testConvA, 2, noWatermark); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(store.paths(testConvA).record); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SaveJoinedGroupState(testConvA, noWatermark, fakeState(3, 1, 0), 3, 1, nil); !errors.Is(err, ErrRekeyRequired) {
		t.Fatalf("join with the file deleted = %v, want ErrRekeyRequired", err)
	}
	assertLatched(t, store, testConvA, RekeyCauseStateMissing)
}

// The first cause is the one kept: a later check that would also have latched
// does not rewrite it.
func TestTheFirstLatchCauseIsKept(t *testing.T) {
	store, _ := newTestStore(t)
	if _, err := store.Reserve(testConvA, 1, ServerWatermark{NextApplicationIndex: 3}); !errors.Is(err, ErrRekeyRequired) {
		t.Fatalf("reserve = %v, want ErrRekeyRequired", err)
	}
	if err := os.Remove(store.paths(testConvA).record); err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	if _, err := store.Reserve(testConvA, 1, noWatermark); !errors.Is(err, ErrRekeyRequired) {
		t.Fatalf("reserve = %v, want ErrRekeyRequired", err)
	}
	assertLatched(t, store, testConvA, RekeyCauseWatermarkAhead)
}

// An anchor that took another leaf's claim before this device's leaf was known
// here is replaced by the first claim that is this device's, not merged with
// it: the higher slot of two chains protects neither.
func TestAnAnchorHoldingAnotherLeafsClaimIsReplacedByThisLeafs(t *testing.T) {
	rec := &Record{Epoch: 4, NextIndex: 2, OwnLeaf: &OwnLeaf{Index: 2, SinceEpoch: 4}}
	stale := Anchor{WatermarkEpoch: 4, WatermarkLeafIndex: 7, WatermarkNextApplication: 30}
	if stale.watermarkAhead(rec, ServerWatermark{}) {
		t.Fatal("another leaf's stored claim was judged against this chain")
	}
	got := stale.advancedBy(rec, ServerWatermark{Epoch: 4, LeafIndex: 2, NextApplicationIndex: 2})
	if got.WatermarkLeafIndex != 2 || got.WatermarkNextApplication != 2 {
		t.Fatalf("anchor after this leaf's claim = %+v", got)
	}
	if !got.watermarkAhead(&Record{Epoch: 4, NextIndex: 1, OwnLeaf: rec.OwnLeaf}, ServerWatermark{}) {
		t.Fatal("this leaf's stored claim stopped protecting its chain")
	}
}
