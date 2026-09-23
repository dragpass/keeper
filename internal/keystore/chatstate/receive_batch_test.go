package chatstate

import (
	"errors"
	"testing"
)

// failingAt opens like fakeInbound until the nth Open, which fails.
type failingAt struct {
	*fakeInbound
	n int
}

func (c *failingAt) Open(m []byte) (Opened, error) {
	if c.opens+1 == c.n {
		c.opens++
		return Opened{}, errors.New("does not open")
	}
	return c.fakeInbound.Open(m)
}

func batchOf(seqs ...uint64) []ReceiveRequest {
	out := make([]ReceiveRequest, 0, len(seqs))
	for _, s := range seqs {
		out = append(out, ReceiveRequest{Seq: s, Message: []byte("wire")})
	}
	return out
}

func TestAReceiveBatchIsOneWrite(t *testing.T) {
	store, _ := newTestStore(t)
	seedGroupState(t, store, testConvA, 0, 0, 0)
	before := readRecordForTest(t, store, testConvA).Generation
	in := inbound(3, 0, "hi")
	in.opened.SenderAccountID, in.opened.SenderDeviceID = "acct", "dev"

	got, err := store.ReceiveBatch(testConvA, noWatermark, batchOf(1, 2), nil, in)
	if err != nil {
		t.Fatal(err)
	}
	rec := readRecordForTest(t, store, testConvA)
	if rec.Generation != before+1 || len(rec.History) != 2 {
		t.Fatalf("generation +%d, history %d; want one write holding both", rec.Generation-before, len(rec.History))
	}
	if got[1].Sender.AccountID != "acct" || got[1].FirstDelivery {
		t.Fatalf("second result = %+v; want the sender, and a redelivery of the same position", got[1])
	}

	// The re-read names the sender from the sealed copy.
	again, err := store.ReceiveBatch(testConvA, noWatermark, batchOf(1), nil, in)
	if err != nil || !again[0].FromHistory || again[0].Sender != (Sender{"acct", "dev"}) {
		t.Fatalf("re-read = %+v, %v", again, err)
	}
}

func TestARefusedReceiveBatchWritesNothing(t *testing.T) {
	store, _ := newTestStore(t)
	seedGroupState(t, store, testConvA, 0, 0, 0)
	before := readRecordForTest(t, store, testConvA).Generation

	if _, err := store.ReceiveBatch(testConvA, noWatermark, batchOf(1, 2),
		nil, &failingAt{fakeInbound: inbound(3, 0, "hi"), n: 2}); err == nil {
		t.Fatal("a batch with a message that does not open succeeded")
	}
	refuse := errors.New("not shown")
	if _, err := store.ReceiveBatch(testConvA, noWatermark, batchOf(1),
		func([]byte) error { return refuse }, inbound(3, 0, "hi")); !errors.Is(err, refuse) {
		t.Fatalf("accept refusal = %v", err)
	}
	if _, err := store.ReceiveBatch(testConvA, noWatermark, batchOf(1),
		nil, &fakeInbound{opened: Opened{Epoch: 0}}); !errors.Is(err, ErrNotApplication) {
		t.Fatalf("a handshake in a display batch = %v", err)
	}
	if rec := readRecordForTest(t, store, testConvA); rec.Generation != before || len(rec.History) != 0 {
		t.Fatal("a refused batch wrote to the record")
	}
	if _, err := store.ReceiveBatch(testConvA, noWatermark, batchOf(1, 1), nil, inbound(3, 0, "hi")); err == nil {
		t.Fatal("a batch naming one seq twice was accepted")
	}
}
