package chatstate

import (
	"errors"
	"testing"
)

const testClientB = "55555555-5555-4555-8555-555555555555"

// scripted opens like fakeInbound except that the nth Open fails with errs[n].
// ErrOwnMessage is how the MLS layer refuses a message from this device's
// own leaf.
type scripted struct {
	*fakeInbound
	errs map[int]error
}

func ownAt(n int, plaintext string) *scripted {
	return &scripted{fakeInbound: inbound(3, 0, plaintext), errs: map[int]error{n: ErrOwnMessage}}
}

func (c *scripted) Open(m []byte) (Opened, error) {
	if err := c.errs[c.opens+1]; err != nil {
		c.opens++
		return Opened{}, err
	}
	return c.fakeInbound.Open(m)
}

func sendForTest(t *testing.T, store *Store, clientMessageID, text string) SendResult {
	t.Helper()
	result, err := store.Send(testConvA, noWatermark, SendRequest{
		ClientMessageID: clientMessageID,
		Plaintext:       []byte(text),
	}, &fakeCipher{})
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	return result
}

// The copy lands with the outbox entry and not before: at the AEAD call the
// disk holds the intent and no copy, and afterwards one write holds both.
func TestSendSealsItsCopyInTheSameWriteAsTheOutboxEntry(t *testing.T) {
	store, _ := newTestStore(t)
	seedGroupState(t, store, testConvA, 4, 2, 7)

	historyAtSeal := -1
	cipher := &fakeCipher{}
	cipher.beforeAt = func() { historyAtSeal = len(readRecordForTest(t, store, testConvA).History) }
	result, err := store.Send(testConvA, noWatermark, SendRequest{
		ClientMessageID: testClientA, Plaintext: []byte("mine"),
	}, cipher)
	if err != nil {
		t.Fatal(err)
	}
	if historyAtSeal != 0 {
		t.Fatalf("the intent write already held %d history entries", historyAtSeal)
	}
	rec := readRecordForTest(t, store, testConvA)
	if rec.Generation != result.Generation || len(rec.Outbox) != 1 || len(rec.History) != 1 {
		t.Fatalf("after the send: generation %d/%d, outbox %d, history %d",
			rec.Generation, result.Generation, len(rec.Outbox), len(rec.History))
	}
	e := rec.History[0]
	if e.ClientMessageID != testClientA || e.Seq != 0 || *e.Position != result.Entry.Position ||
		e.SenderAccountID != fakeSelf.AccountID || e.SenderDeviceID != fakeSelf.DeviceID {
		t.Fatalf("sent copy = %+v; want this device at the send position, unbound", e)
	}

	// A retransmission answers from the outbox and seals nothing again.
	sendForTest(t, store, testClientA, "mine")
	if n := len(readRecordForTest(t, store, testConvA).History); n != 1 {
		t.Fatalf("a retransmission left %d copies", n)
	}
}

func TestAFailedSendKeepsNoCopy(t *testing.T) {
	store, _ := newTestStore(t)
	seedGroupState(t, store, testConvA, 1, 0, 0)
	if _, err := store.Send(testConvA, noWatermark, SendRequest{
		ClientMessageID: testClientA, Plaintext: []byte("lost"),
	}, &fakeCipher{sealErr: errors.New("aead refused")}); err == nil {
		t.Fatal("the send succeeded")
	}
	if n := len(readRecordForTest(t, store, testConvA).History); n != 0 {
		t.Fatalf("a failed send left %d copies", n)
	}
}

func TestMarkSentBindsTheCopyToItsSeqOnce(t *testing.T) {
	store, _ := newTestStore(t)
	seedGroupState(t, store, testConvA, 1, 0, 0)
	sent := sendForTest(t, store, testClientA, "mine")

	first, err := store.MarkSent(testConvA, noWatermark, testClientA, 9)
	if err != nil || !first.Bound {
		t.Fatalf("mark sent = %+v, %v", first, err)
	}
	again, err := store.MarkSent(testConvA, noWatermark, testClientA, 9)
	if err != nil || again.Bound || again.Generation != first.Generation {
		t.Fatalf("mark sent again = %+v, %v; want nothing written", again, err)
	}

	got, err := store.ReadHistory(testConvA, noWatermark, 9)
	if err != nil || string(got.Plaintext) != "mine" || !got.FromHistory ||
		got.Sender != fakeSelf || got.Position != sent.Entry.Position {
		t.Fatalf("read of the bound seq = %+v, %v", got, err)
	}
}

func TestMarkSentRefusesEveryOtherBindingAndWritesNothing(t *testing.T) {
	store, _ := newTestStore(t)
	seedGroupState(t, store, testConvA, 1, 0, 0)
	sendForTest(t, store, testClientA, "first")
	sendForTest(t, store, testClientB, "second")
	if _, err := store.MarkSent(testConvA, noWatermark, testClientA, 9); err != nil {
		t.Fatal(err)
	}
	// A delivered message holds seq 12.
	if _, err := store.Receive(testConvA, noWatermark,
		ReceiveRequest{Seq: 12, Message: []byte("wire")}, inbound(3, 0, "theirs")); err != nil {
		t.Fatal(err)
	}
	before := readRecordForTest(t, store, testConvA).Generation

	for name, tc := range map[string]struct {
		id   string
		seq  uint64
		want error
	}{
		"a seq another sent message holds":     {testClientB, 9, ErrSeqBound},
		"a seq a delivered message holds":      {testClientB, 12, ErrSeqBound},
		"a second seq for a bound message":     {testClientA, 10, ErrSeqBound},
		"a message this device has no copy of": {"66666666-6666-4666-8666-666666666666", 13, ErrNotFound},
	} {
		if _, err := store.MarkSent(testConvA, noWatermark, tc.id, tc.seq); !errors.Is(err, tc.want) {
			t.Errorf("%s = %v; want %v", name, err, tc.want)
		}
	}
	if _, err := store.MarkSent(testConvA, noWatermark, testClientB, 0); err == nil {
		t.Error("seq 0 was accepted")
	}
	if got := readRecordForTest(t, store, testConvA).Generation; got != before {
		t.Fatalf("a refused mark sent wrote the record (%d -> %d)", before, got)
	}
	if got, err := store.ReadHistory(testConvA, noWatermark, 12); err != nil || string(got.Plaintext) != "theirs" {
		t.Fatalf("the delivered message was disturbed: %+v, %v", got, err)
	}
}

// Sent copies live under the received history's retention: the same ring,
// and unbound copies do not displace each other.
func TestSentCopiesShareTheHistoryRing(t *testing.T) {
	store, _ := newTestStore(t)
	store.HistoryPolicy.MaxEntries = 2
	seedGroupState(t, store, testConvA, 1, 0, 0)
	sendForTest(t, store, testClientA, "one")
	sendForTest(t, store, testClientB, "two")
	if n := len(readRecordForTest(t, store, testConvA).History); n != 2 {
		t.Fatalf("two unbound copies left %d entries", n)
	}
	sendForTest(t, store, "66666666-6666-4666-8666-666666666666", "three")
	if _, err := store.MarkSent(testConvA, noWatermark, testClientA, 4); !errors.Is(err, ErrNotFound) {
		t.Fatalf("mark sent of an evicted copy = %v", err)
	}
	if _, err := store.MarkSent(testConvA, noWatermark, testClientB, 5); err != nil {
		t.Fatalf("mark sent of a kept copy = %v", err)
	}
}

// Own messages in a display batch: a bound one comes from its copy without
// MLS, one without a copy is reported without plaintext, and neither stops
// the other messages from being delivered in the same single write.
func TestADisplayBatchAnswersThisDevicesOwnMessages(t *testing.T) {
	store, _ := newTestStore(t)
	seedGroupState(t, store, testConvA, 0, 0, 0)
	sendForTest(t, store, testClientA, "bound")
	if _, err := store.MarkSent(testConvA, noWatermark, testClientA, 1); err != nil {
		t.Fatal(err)
	}
	before := readRecordForTest(t, store, testConvA).Generation

	in := ownAt(1, "theirs")
	in.opened.SenderAccountID, in.opened.SenderDeviceID = "acct", "dev"
	got, err := store.ReceiveBatch(testConvA, noWatermark, batchOf(1, 2, 3), nil, in)
	if err != nil || len(got) != 3 {
		t.Fatalf("batch = %+v, %v", got, err)
	}
	if string(got[0].Plaintext) != "bound" || !got[0].FromHistory || got[0].Sender != fakeSelf {
		t.Fatalf("bound own message = %+v", got[0])
	}
	if !got[1].OwnWithoutCopy || got[1].Plaintext != nil || got[1].FromHistory {
		t.Fatalf("own message without a copy = %+v", got[1])
	}
	if string(got[2].Plaintext) != "theirs" || got[2].OwnWithoutCopy {
		t.Fatalf("the other member's message = %+v", got[2])
	}
	if in.opens != 2 {
		t.Fatalf("MLS was asked to open %d messages; the bound one needs none", in.opens)
	}
	rec := readRecordForTest(t, store, testConvA)
	if rec.Generation != before+1 || len(rec.History) != 2 {
		t.Fatalf("generation +%d, history %d; want one write adding only the delivered message",
			rec.Generation-before, len(rec.History))
	}

	// A page of nothing but an own message without a copy writes nothing.
	only := ownAt(1, "x")
	if got, err := store.ReceiveBatch(testConvA, noWatermark, batchOf(4), nil, only); err != nil || !got[0].OwnWithoutCopy {
		t.Fatalf("own-only batch = %+v, %v", got, err)
	}
	if readRecordForTest(t, store, testConvA).Generation != rec.Generation {
		t.Fatal("an own-only batch wrote the record")
	}
}

// The exception is ErrOwnMessage and nothing else: a batch holding an own
// message and one that fails is refused whole.
func TestAnOwnMessageDoesNotExcuseAnotherFailure(t *testing.T) {
	store, _ := newTestStore(t)
	seedGroupState(t, store, testConvA, 0, 0, 0)
	before := readRecordForTest(t, store, testConvA).Generation
	mixed := ownAt(1, "hi")
	mixed.errs[3] = errors.New("does not open")
	if got, err := store.ReceiveBatch(testConvA, noWatermark, batchOf(1, 2, 3), nil, mixed); err == nil || got != nil {
		t.Fatalf("a batch with a failing message = %+v, %v", got, err)
	}
	if rec := readRecordForTest(t, store, testConvA); rec.Generation != before || len(rec.History) != 0 {
		t.Fatal("a refused batch wrote the record")
	}
}

func ownRow(seq uint64, sent SendResult) ReceiveRequest {
	return ReceiveRequest{Seq: seq, Message: append([]byte(nil), sent.Entry.Ciphertext...)}
}

// The process died between POST /:id/messages and mls_mark_sent. The server's
// row carries the exact bytes of our outbox entry, so the display batch binds
// the copy to that seq and shows it, in the batch's one write.
func TestADisplayBatchBindsAnOwnMessageMarkSentNeverReached(t *testing.T) {
	store, _ := newTestStore(t)
	seedGroupState(t, store, testConvA, 0, 0, 0)
	sent := sendForTest(t, store, testClientA, "mine")
	before := readRecordForTest(t, store, testConvA).Generation

	in := ownAt(1, "theirs")
	in.opened.SenderAccountID, in.opened.SenderDeviceID = "acct", "dev"
	got, err := store.ReceiveBatch(testConvA, noWatermark, []ReceiveRequest{ownRow(7, sent), {Seq: 8, Message: []byte("m8")}}, nil, in)
	if err != nil || len(got) != 2 {
		t.Fatalf("batch = %+v, %v", got, err)
	}
	if string(got[0].Plaintext) != "mine" || !got[0].FromHistory || got[0].OwnWithoutCopy || got[0].Sender != fakeSelf ||
		got[0].Position != sent.Entry.Position {
		t.Fatalf("own message = %+v", got[0])
	}
	if string(got[1].Plaintext) != "theirs" {
		t.Fatalf("the other member's message = %+v", got[1])
	}
	rec := readRecordForTest(t, store, testConvA)
	if i, ok := rec.findSentHistory(testClientA); !ok || rec.History[i].Seq != 7 || rec.Generation != before+1 {
		t.Fatalf("history %+v at generation +%d; want the copy bound to 7 in one write", rec.History, rec.Generation-before)
	}

	// A late mark sent finds the pair already there, and a re-read needs no MLS.
	if got, err := store.MarkSent(testConvA, noWatermark, testClientA, 7); err != nil || got.Bound {
		t.Fatalf("mark sent after the bind = %+v, %v", got, err)
	}
	again := ownAt(1, "")
	if got, err := store.ReceiveBatch(testConvA, noWatermark, []ReceiveRequest{ownRow(7, sent)}, nil, again); err != nil ||
		string(got[0].Plaintext) != "mine" || again.opens != 0 {
		t.Fatalf("re-read = %+v, %v (opens %d)", got, err, again.opens)
	}
	// The same bytes under another seq do not move the copy.
	moved, err := store.ReceiveBatch(testConvA, noWatermark, []ReceiveRequest{ownRow(9, sent)}, nil, ownAt(1, ""))
	if err != nil || !moved[0].OwnWithoutCopy || moved[0].Plaintext != nil {
		t.Fatalf("own bytes under a second seq = %+v, %v", moved, err)
	}
}

// Only our own outbox bytes bind, and only in a batch that is written.
func TestAnOwnMessageBindsOnlyOnExactBytesInAWrittenBatch(t *testing.T) {
	store, _ := newTestStore(t)
	seedGroupState(t, store, testConvA, 0, 0, 0)
	sent := sendForTest(t, store, testClientA, "mine")
	unbound := func() {
		t.Helper()
		rec := readRecordForTest(t, store, testConvA)
		if i, _ := rec.findSentHistory(testClientA); rec.History[i].Seq != 0 {
			t.Fatalf("the copy was bound to %d", rec.History[i].Seq)
		}
	}

	other := ownRow(7, sent)
	other.Message[len(other.Message)-1] ^= 1
	if got, err := store.ReceiveBatch(testConvA, noWatermark, []ReceiveRequest{other}, nil, ownAt(1, "")); err != nil || !got[0].OwnWithoutCopy {
		t.Fatalf("near-identical bytes = %+v, %v", got, err)
	}
	unbound()

	failing := ownAt(1, "theirs")
	failing.errs[2] = errors.New("does not open")
	if got, err := store.ReceiveBatch(testConvA, noWatermark, []ReceiveRequest{ownRow(7, sent), {Seq: 8, Message: []byte("m8")}}, nil, failing); err == nil || got != nil {
		t.Fatalf("a batch with a failing message = %+v, %v", got, err)
	}
	unbound()
}
