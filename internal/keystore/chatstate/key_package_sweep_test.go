package chatstate

import (
	"errors"
	"testing"
	"time"
)

// The pool sweep deletes a claimed entry only once its conversation's record
// names it: a claim whose join never wrote keeps its keys, and so does an
// entry nobody claimed.
func TestKeyPackagePool_TheSweepDeletesOnlyWhatAJoinedRecordNames(t *testing.T) {
	store, _ := newTestStore(t)
	joined, pending, idle := poolEntry(1, poolNow.Add(time.Hour)), poolEntry(2, poolNow.Add(time.Hour)), poolEntry(3, poolNow.Add(time.Hour))
	if err := store.AddKeyPackages([]KeyPackagePoolEntry{joined, pending, idle}, poolNow); err != nil {
		t.Fatal(err)
	}
	if err := store.ClaimKeyPackage(joined.Ref, testConvA); err != nil {
		t.Fatal(err)
	}
	if err := store.ClaimKeyPackage(pending.Ref, testConvB); err != nil {
		t.Fatal(err)
	}
	// The join into A wrote its state and stopped before its delete; the join
	// into B never wrote.
	if _, err := store.SaveJoinedGroupState(testConvA, noWatermark, fakeState(2, 1, 0), 2, 1, joined.Ref); err != nil {
		t.Fatal(err)
	}

	if n, err := store.KeyPackagePoolSize(poolNow); err != nil || n != 2 {
		t.Fatalf("pool size after the sweep = %d, %v; want 2", n, err)
	}
	if _, err := store.LookupKeyPackage([][]byte{joined.Ref}, poolNow); !errors.Is(err, ErrKeyPackageNotInPool) {
		t.Fatalf("the consumed entry survived the sweep: %v", err)
	}
	for _, kept := range []KeyPackagePoolEntry{pending, idle} {
		if _, err := store.LookupKeyPackage([][]byte{kept.Ref}, poolNow); err != nil {
			t.Fatalf("an entry the sweep had no proof for was deleted: %v", err)
		}
	}
}

// A claim is idempotent and a claim for an entry that is gone is nothing to do.
func TestKeyPackagePool_AClaimOfAMissingEntryIsANoOp(t *testing.T) {
	store, _ := newTestStore(t)
	e := poolEntry(1, poolNow.Add(time.Hour))
	if err := store.ClaimKeyPackage(e.Ref, testConvA); err != nil {
		t.Fatalf("claim on an empty pool = %v", err)
	}
	if err := store.AddKeyPackages([]KeyPackagePoolEntry{e}, poolNow); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := store.ClaimKeyPackage(e.Ref, testConvA); err != nil {
			t.Fatal(err)
		}
	}
	if n, _ := store.KeyPackagePoolSize(poolNow); n != 1 {
		t.Fatalf("pool size after a claim = %d, want 1", n)
	}
}
