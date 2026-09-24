package chatstate

import (
	"slices"
	"testing"
)

func TestStatusReportsTheRecordAndWritesNothing(t *testing.T) {
	store, _ := newTestStore(t)
	empty, err := store.Status(testConvA, noWatermark, &fakeInbound{})
	if err != nil || empty.HasGroupState || empty.NeedsRekey || empty.RemovalLatch == nil {
		t.Fatalf("status of a fresh conversation = %+v, %v", empty, err)
	}

	if _, err := store.SaveJoinedGroupState(testConvA, noWatermark, fakeState(3, 1, 0), 3, 1, nil); err != nil {
		t.Fatal(err)
	}
	before := readRecordForTest(t, store, testConvA).Generation
	wm := ServerWatermark{PendingRemovals: []string{"bob", "carol"}}
	got, err := store.Status(testConvA, wm, &fakeInbound{roster: []string{"alice", "bob"}})
	if err != nil {
		t.Fatal(err)
	}
	if got.Epoch != 3 || !got.HasGroupState || got.CommitPending || !slices.Equal(got.RemovalLatch, []string{"bob"}) {
		t.Fatalf("status = %+v", got)
	}
	rec := readRecordForTest(t, store, testConvA)
	if rec.Generation != before || len(rec.RemovalLatch) != 0 {
		t.Fatal("a status read wrote to the record")
	}

	// A rewind found by the read is latched and reported, and nothing else is.
	// The watermark names the leaf this device joined as; another leaf's
	// chain would not be this device's to be behind on.
	ahead := ServerWatermark{Epoch: 9, LeafIndex: 1, NextApplicationIndex: 1}
	rewound, err := store.Status(testConvA, ahead, &fakeInbound{})
	if err != nil || !rewound.NeedsRekey || rewound.HasGroupState || rewound.RekeyCause != RekeyCauseWatermarkAhead {
		t.Fatalf("status of a rewound record = %+v, %v", rewound, err)
	}
	if again, _ := store.Status(testConvA, noWatermark, &fakeInbound{}); !again.NeedsRekey {
		t.Fatal("the rewind latch did not hold")
	}
}
