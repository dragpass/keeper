package chatstate

import (
	"errors"
	"testing"
)

func senderInbound() *fakeInbound {
	in := inbound(3, 0, "hi")
	in.opened.SenderAccountID, in.opened.SenderDeviceID = "acct", "dev"
	return in
}

// Ring of three, five delivered, then the page from seq 1 again with one new
// message: the two evicted seqs are answered as unavailable without reaching
// MLS, the three held ones from history, and the new one is opened.
func TestAReceiveBatchAnswersAnEvictedSeqWithoutOpeningIt(t *testing.T) {
	store, _ := newTestStore(t)
	store.HistoryPolicy.MaxEntries = 3
	seedGroupState(t, store, testConvA, 0, 0, 0)
	if _, err := store.ReceiveBatch(testConvA, noWatermark, batchOf(1, 2, 3, 4, 5), nil, senderInbound()); err != nil {
		t.Fatal(err)
	}

	in := senderInbound()
	got, err := store.ReceiveBatch(testConvA, noWatermark, batchOf(1, 2, 3, 4, 5, 6), nil, in)
	if err != nil {
		t.Fatalf("re-read past the ring = %v", err)
	}
	for i, r := range got {
		switch {
		case i < 2:
			if !r.HistoryUnavailable || r.Plaintext != nil || r.FromHistory || r.Sender != (Sender{}) {
				t.Fatalf("evicted seq %d = %+v", i+1, r)
			}
		case i < 5:
			if !r.FromHistory || r.HistoryUnavailable || string(r.Plaintext) != "hi" {
				t.Fatalf("held seq %d = %+v", i+1, r)
			}
		default:
			if r.FromHistory || r.HistoryUnavailable || string(r.Plaintext) != "hi" {
				t.Fatalf("new seq %d = %+v", i+1, r)
			}
		}
	}
	if in.opens != 1 {
		t.Fatalf("MLS opened %d messages; want only the new one", in.opens)
	}

	// The single-message path refuses the same seq rather than opening it.
	if _, err := store.Receive(testConvA, noWatermark, ReceiveRequest{Seq: 1, Message: []byte("wire")}, in); !errors.Is(err, ErrHistoryUnavailable) {
		t.Fatalf("receive of an evicted seq = %v, want ErrHistoryUnavailable", err)
	}
	if in.opens != 1 {
		t.Fatal("the single-message path handed an evicted seq to MLS")
	}
}

// An integrity failure still refuses the page: only an evicted seq is let
// through, and a message that does not open refuses everything around it.
func TestAnEvictedSeqDoesNotExcuseAMessageThatDoesNotOpen(t *testing.T) {
	store, _ := newTestStore(t)
	store.HistoryPolicy.MaxEntries = 1
	seedGroupState(t, store, testConvA, 0, 0, 0)
	if _, err := store.ReceiveBatch(testConvA, noWatermark, batchOf(1, 2), nil, senderInbound()); err != nil {
		t.Fatal(err)
	}
	before := readRecordForTest(t, store, testConvA).Generation
	if _, err := store.ReceiveBatch(testConvA, noWatermark, batchOf(1, 3),
		nil, &failingAt{fakeInbound: senderInbound(), n: 1}); err == nil {
		t.Fatal("a page with a message that does not open succeeded")
	}
	if readRecordForTest(t, store, testConvA).Generation != before {
		t.Fatal("a refused page wrote to the record")
	}
}

// A latched conversation answers an evicted seq the same way, and still
// refuses a seq it never opened.
func TestALatchedConversationAnswersAnEvictedSeqAsUnavailable(t *testing.T) {
	store, _ := newTestStore(t)
	store.HistoryPolicy.MaxEntries = 1
	seedGroupState(t, store, testConvA, 0, 0, 0)
	if _, err := store.ReceiveBatch(testConvA, noWatermark, batchOf(1, 2), nil, senderInbound()); err != nil {
		t.Fatal(err)
	}
	ahead := ServerWatermark{Epoch: 9, NextApplicationIndex: 1}
	if _, err := store.ReadOutbox(testConvA, ahead, testClientA); !errors.Is(err, ErrRekeyRequired) {
		t.Fatalf("latch = %v", err)
	}
	got, err := store.ReceiveBatch(testConvA, noWatermark, batchOf(1, 2), nil, senderInbound())
	if err != nil || !got[0].HistoryUnavailable || !got[1].FromHistory {
		t.Fatalf("latched page = %+v, %v", got, err)
	}
	if _, err := store.ReceiveBatch(testConvA, noWatermark, batchOf(2, 3), nil, senderInbound()); !errors.Is(err, ErrRekeyRequired) {
		t.Fatalf("latched page with a never-opened seq = %v, want ErrRekeyRequired", err)
	}
}

// The opened set stays small for an in-order conversation, is bounded for an
// out-of-order one, and fills the lowest gap when it has to give.
func TestOpenedSeqsMergeAndStayBounded(t *testing.T) {
	var rec Record
	for _, seq := range []uint64{1, 2, 3, 5, 4} {
		rec.markOpened(seq, HistoryPolicy{})
	}
	if len(rec.OpenedSeqs) != 1 || rec.OpenedSeqs[0] != (SeqRange{1, 5}) {
		t.Fatalf("in-order seqs = %+v", rec.OpenedSeqs)
	}
	var sparse Record
	for i := range MaxOpenedSeqRanges + 5 {
		sparse.markOpened(uint64(10+2*i), HistoryPolicy{})
	}
	if len(sparse.OpenedSeqs) != MaxOpenedSeqRanges {
		t.Fatalf("ranges = %d, want the bound", len(sparse.OpenedSeqs))
	}
	if !sparse.opened(11, HistoryPolicy{}) || sparse.opened(9, HistoryPolicy{}) {
		t.Fatal("the overflow did not fill the lowest gap, or reached below the lowest seq")
	}
	if last := sparse.OpenedSeqs[len(sparse.OpenedSeqs)-1]; last.Through != uint64(10+2*(MaxOpenedSeqRanges+4)) {
		t.Fatalf("the newest seq was lost: %+v", last)
	}
}

// A record written before OpenedSeqs existed, whose ring is full, reads every
// seq below its oldest held copy as opened; one whose ring never filled
// evicted nothing and reads none.
func TestALegacyRecordInfersItsOpenedSeqsOnlyFromAFullRing(t *testing.T) {
	full := Record{History: []HistoryEntry{{Seq: 70}, {Seq: 71}, {Seq: 72}}}
	policy := HistoryPolicy{MaxEntries: 3}
	if !full.opened(69, policy) || full.opened(73, policy) {
		t.Fatal("a full legacy ring did not read the seqs below it as opened")
	}
	full.markOpened(73, policy)
	if !full.opened(1, policy) || !full.opened(73, policy) {
		t.Fatalf("the first mark dropped the inferred floor: %+v", full.OpenedSeqs)
	}
	partial := Record{History: []HistoryEntry{{Seq: 70}}}
	if partial.opened(69, policy) {
		t.Fatal("a legacy ring that never filled inferred an opened seq")
	}
}
