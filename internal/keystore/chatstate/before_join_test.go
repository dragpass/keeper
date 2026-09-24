package chatstate

import (
	"errors"
	"testing"
)

func framedAt(seq, epoch uint64) ReceiveRequest {
	return ReceiveRequest{Seq: seq, Message: []byte("wire"), FramedEpoch: &epoch}
}

// Joined at epoch 4: a message claiming epoch 3 is answered as BeforeJoin
// without reaching MLS, one at epoch 4 is opened, and a latched record answers
// the pre-join one the same way while still refusing a seq it never opened.
func TestAReceiveBatchAnswersAMessageFromBeforeTheJoinWithoutOpeningIt(t *testing.T) {
	store, _ := newTestStore(t)
	if _, err := store.SaveJoinedGroupState(testConvA, noWatermark, fakeState(4, 2, 0), 4, 2, nil); err != nil {
		t.Fatal(err)
	}
	in := senderInbound()
	in.opened.Epoch = 4
	got, err := store.ReceiveBatch(testConvA, noWatermark,
		[]ReceiveRequest{framedAt(1, 3), framedAt(2, 4), {Seq: 3, Message: []byte("wire")}}, nil, in)
	if err != nil {
		t.Fatalf("page with a pre-join message = %v", err)
	}
	if r := got[0]; !r.BeforeJoin || r.HistoryUnavailable || r.Plaintext != nil || r.Sender != (Sender{}) {
		t.Fatalf("pre-join seq = %+v", r)
	}
	if got[1].BeforeJoin || string(got[1].Plaintext) != "hi" || got[2].BeforeJoin {
		t.Fatalf("joined-epoch seqs = %+v", got[1:])
	}
	if in.opens != 2 {
		t.Fatalf("MLS opened %d messages; want the two with no pre-join claim", in.opens)
	}
	if readRecordForTest(t, store, testConvA).opened(1, store.HistoryPolicy) {
		t.Fatal("the pre-join seq was marked opened")
	}

	ahead := ServerWatermark{Epoch: 9, LeafIndex: 2, NextApplicationIndex: 1}
	if _, err := store.ReadOutbox(testConvA, ahead, testClientA); !errors.Is(err, ErrRekeyRequired) {
		t.Fatalf("latch = %v", err)
	}
	latched, err := store.ReceiveBatch(testConvA, noWatermark, []ReceiveRequest{framedAt(1, 3), framedAt(2, 4)}, nil, senderInbound())
	if err != nil || !latched[0].BeforeJoin || !latched[1].FromHistory {
		t.Fatalf("latched page = %+v, %v", latched, err)
	}
	if _, err := store.ReceiveBatch(testConvA, noWatermark, []ReceiveRequest{framedAt(9, 4)}, nil, senderInbound()); !errors.Is(err, ErrRekeyRequired) {
		t.Fatalf("latched never-opened seq at the join epoch = %v, want ErrRekeyRequired", err)
	}
}

// A record that does not know where its leaf entered (no OwnLeaf: a group
// seeded before it existed) cannot tell, and hands the message to MLS as
// before.
func TestARecordWithoutItsJoinEpochOpensEveryMessage(t *testing.T) {
	store, _ := newTestStore(t)
	seedGroupState(t, store, testConvA, 4, 2, 0)
	in := senderInbound()
	in.opened.Epoch = 4
	got, err := store.ReceiveBatch(testConvA, noWatermark, []ReceiveRequest{framedAt(1, 0)}, nil, in)
	if err != nil || got[0].BeforeJoin || in.opens != 1 {
		t.Fatalf("got %+v, %v, %d opens", got, err, in.opens)
	}
}
