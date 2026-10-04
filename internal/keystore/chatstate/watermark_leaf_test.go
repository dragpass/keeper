// watermark_leaf_test.go — the watermark's leaf slot: whose chain the server
// is describing. These ran through chat_state_reserve_send at the protocol
// edge until that action was removed; the rule lives in Record.ownsChain, so
// they now drive it through the store.

package chatstate

import (
	"bytes"
	"errors"
	"testing"
)

// seedSendPositionAtLeaf puts one outbox entry in the record under a position
// that names its ratchet and its leaf, which is what the MLS send path writes
// and what teaches the record whose leaf it is on.
func seedSendPositionAtLeaf(t *testing.T, store *Store, leaf uint32) {
	t.Helper()
	reservation, err := store.Reserve(testConvA, 1, noWatermark)
	if err != nil {
		t.Fatalf("seed reserve: %v", err)
	}
	if _, _, err := store.CommitOutbox(testConvA, noWatermark, OutboxEntry{
		ClientMessageID: testClientA,
		Position: Position{
			SenderLeafIndex: leaf,
			ContentType:     ContentTypeApplication,
			Generation:      reservation.FirstChainIndex,
		},
		IV:         bytes.Repeat([]byte{7}, ivBytes),
		Ciphertext: bytes.Repeat([]byte{9}, 32),
	}); err != nil {
		t.Fatalf("seed outbox: %v", err)
	}
}

// leafWatermark carries one accepted application position on the named leaf.
// The epoch stays at the record's so the rollback axes have nothing else to
// say and the leaf slot is the only thing under test.
func leafWatermark(leaf uint32, nextApplication uint64) ServerWatermark {
	return ServerWatermark{LeafIndex: leaf, NextApplicationIndex: nextApplication}
}

// A watermark describing another leaf's chain is not used to judge this one's:
// it is ignored rather than refused, so it neither latches nor moves the
// anchor, and the chain it would have judged carries on from where it was.
// Refusing it would lock out a second device of the account, which is handed
// the other device's chain because the server keeps one watermark per
// account.
func TestAWatermarkNamingAnotherLeafIsIgnored(t *testing.T) {
	store, _ := newTestStore(t)
	seedSendPositionAtLeaf(t, store, 3)

	if _, err := store.Reserve(testConvA, 1, leafWatermark(9, 5)); err != nil {
		t.Fatalf("a watermark on another leaf was judged against this one: %v", err)
	}
	if _, err := store.Reserve(testConvA, 1, leafWatermark(3, 1)); err != nil {
		t.Fatalf("a watermark on this device's own leaf was refused: %v", err)
	}
	if _, err := store.Reserve(testConvA, 1, leafWatermark(3, 9)); !errors.Is(err, ErrRekeyRequired) {
		t.Fatalf("a watermark ahead on this device's own leaf = %v, want ErrRekeyRequired", err)
	}
}

// Until the server has accepted a position there is no chain for the leaf slot
// to name, so it carries nothing and is ignored — including on the first send,
// where this device's leaf is non-zero and the watermark is all zeros.
func TestAnEmptyWatermarkIgnoresItsLeafSlot(t *testing.T) {
	store, _ := newTestStore(t)
	seedSendPositionAtLeaf(t, store, 3)

	if _, err := store.Reserve(testConvA, 1, leafWatermark(9, 0)); err != nil {
		t.Fatalf("a watermark that has accepted nothing was judged on its leaf: %v", err)
	}
}

// A conversation that has never sent has no leaf of its own to compare, which
// is the same answer as a conversation with no group state: the slot is not
// invented and the call is not refused on it.
func TestAWatermarkLeafIsIgnoredBeforeThisDeviceHasALeaf(t *testing.T) {
	store, _ := newTestStore(t)

	if _, err := store.Reserve(testConvA, 1, leafWatermark(9, 0)); err != nil {
		t.Fatalf("a conversation with no leaf was refused on a leaf: %v", err)
	}
}
