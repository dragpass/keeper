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

// A conversation latched NeedsRekey stays readable from its history and from
// nothing else: re-reads are answered without MLS, anything the history does
// not hold refuses the whole batch, and nothing clears the latch.
func TestALatchedConversationStillReadsItsHistory(t *testing.T) {
	store, secrets := newTestStore(t)
	seedGroupState(t, store, testConvA, 0, 0, 0)
	in := inbound(3, 0, "before the rewind")
	in.opened.SenderAccountID, in.opened.SenderDeviceID = "acct", "dev"
	if _, err := store.ReceiveBatch(testConvA, noWatermark, batchOf(1, 2), nil, in); err != nil {
		t.Fatal(err)
	}
	// A server that accepted positions this record never saw: the next load
	// latches.
	ahead := ServerWatermark{Epoch: 9, NextApplicationIndex: 1}
	if _, err := store.Reserve(testConvA, 1, ahead); !errors.Is(err, ErrRekeyRequired) {
		t.Fatalf("reserve on a rewound record = %v", err)
	}
	before := readRecordForTest(t, store, testConvA).Generation
	opens := in.opens

	got, err := store.ReceiveBatch(testConvA, noWatermark, batchOf(1, 2), nil, in)
	if err != nil || len(got) != 2 || !got[0].FromHistory || !got[1].FromHistory ||
		string(got[0].Plaintext) != "before the rewind" || got[1].Sender != (Sender{"acct", "dev"}) {
		t.Fatalf("a history-only batch under the latch = %+v, %v", got, err)
	}
	if one, err := store.ReadHistory(testConvA, noWatermark, 2); err != nil || !one.FromHistory {
		t.Fatalf("read history under the latch = %+v, %v", one, err)
	}
	if _, err := store.ReadHistory(testConvA, noWatermark, 7); !errors.Is(err, ErrHistoryUnavailable) {
		t.Fatalf("read history of an unknown seq under the latch = %v", err)
	}

	for name, reqs := range map[string][]ReceiveRequest{
		"a new message":           batchOf(3),
		"history and one new one": batchOf(1, 3),
	} {
		if got, err := store.ReceiveBatch(testConvA, noWatermark, reqs, nil, in); !errors.Is(err, ErrRekeyRequired) || got != nil {
			t.Fatalf("%s under the latch = %+v, %v; want ErrRekeyRequired and nothing", name, got, err)
		}
	}
	if _, err := store.Receive(testConvA, noWatermark, ReceiveRequest{Seq: 3, Message: []byte("wire")}, in); !errors.Is(err, ErrRekeyRequired) {
		t.Fatalf("a single receive under the latch = %v", err)
	}
	if in.opens != opens {
		t.Fatalf("MLS was asked to open %d messages under the latch", in.opens-opens)
	}
	if rec := readRecordForTest(t, store, testConvA); rec.Generation != before {
		t.Fatal("a read under the latch wrote the record")
	}
	anchor, err := loadAnchor(secrets, store.paths(testConvA).tag)
	if err != nil || !anchor.NeedsRekey {
		t.Fatalf("the latch did not hold: %+v, %v", anchor, err)
	}
}
