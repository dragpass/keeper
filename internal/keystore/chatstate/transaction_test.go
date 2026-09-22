// transaction_test.go — the send and receive transactions, driven through a
// stand-in for the MLS layer.
//
// The stand-in models the one property the ordering has to defend against and
// that a simple counter does not have: **which position gets used is decided by
// the state that was loaded, not by a number the caller carries.** That is why
// reserving under a lock and encrypting after it does not work with MLS, and a
// fake that took the position from its argument would pass a test the real
// library fails.
//
// Tests that need the real library are in internal/keystore/mls.

package chatstate

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"
)

// fakeCipher is a one-axis ratchet whose position comes out of the blob it was
// loaded from. Seal records the position it used inside the ciphertext so a
// test can take two ciphertexts apart and see whether they collided, rather
// than believing the numbers the store reported.
type fakeCipher struct {
	epoch      uint64
	leaf       uint32
	generation uint64
	loaded     bool

	burns    int
	seals    int
	opens    int
	lastAAD  []byte
	sealErr  error
	beforeAt func()
}

func fakeState(epoch uint64, leaf uint32, generation uint64) []byte {
	return fmt.Appendf(nil, "fake|%d|%d|%d", epoch, leaf, generation)
}

func (c *fakeCipher) Load(blob []byte) error {
	fields := strings.Split(string(blob), "|")
	if len(fields) != 4 || fields[0] != "fake" {
		return errors.New("fake cipher: unusable state blob")
	}
	epoch, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		return err
	}
	leaf, err := strconv.ParseUint(fields[2], 10, 32)
	if err != nil {
		return err
	}
	generation, err := strconv.ParseUint(fields[3], 10, 64)
	if err != nil {
		return err
	}
	c.epoch, c.leaf, c.generation, c.loaded = epoch, uint32(leaf), generation, true
	return nil
}

func (c *fakeCipher) Peek() (Position, error) {
	if !c.loaded {
		return Position{}, errors.New("fake cipher: peeked before loading")
	}
	return Position{
		Epoch:           c.epoch,
		SenderLeafIndex: c.leaf,
		ContentType:     ContentTypeApplication,
		Generation:      c.generation,
	}, nil
}

func (c *fakeCipher) Burn() error {
	if !c.loaded {
		return errors.New("fake cipher: burned before loading")
	}
	c.generation++
	c.burns++
	return nil
}

func (c *fakeCipher) Seal(plaintext, authenticatedData []byte) ([]byte, error) {
	if !c.loaded {
		return nil, errors.New("fake cipher: sealed before loading")
	}
	if c.beforeAt != nil {
		c.beforeAt()
	}
	if c.sealErr != nil {
		return nil, c.sealErr
	}
	used := c.generation
	c.generation++
	c.seals++
	c.lastAAD = append([]byte(nil), authenticatedData...)
	return fmt.Appendf(nil, "ct|%d|%d|%d|%s", c.epoch, c.leaf, used, plaintext), nil
}

func (c *fakeCipher) State() ([]byte, error) {
	if !c.loaded {
		return nil, errors.New("fake cipher: serialized before loading")
	}
	return fakeState(c.epoch, c.leaf, c.generation), nil
}

// positionOf takes a ciphertext apart. Two sends must never produce the same
// answer here.
func positionOf(t *testing.T, ciphertext []byte) Position {
	t.Helper()
	fields := strings.SplitN(string(ciphertext), "|", 5)
	if len(fields) != 5 || fields[0] != "ct" {
		t.Fatalf("unrecognized ciphertext %q", ciphertext)
	}
	epoch, _ := strconv.ParseUint(fields[1], 10, 64)
	leaf, _ := strconv.ParseUint(fields[2], 10, 32)
	generation, _ := strconv.ParseUint(fields[3], 10, 64)
	return Position{
		Epoch:           epoch,
		SenderLeafIndex: uint32(leaf),
		ContentType:     ContentTypeApplication,
		Generation:      generation,
	}
}

// seedGroupState puts a starting state in the record so Send has something to
// load.
func seedGroupState(t *testing.T, store *Store, conversationID string, epoch uint64, leaf uint32, generation uint64) {
	t.Helper()
	if _, err := store.SaveGroupState(
		conversationID, noWatermark, fakeState(epoch, leaf, generation),
	); err != nil {
		t.Fatalf("seed group state: %v", err)
	}
}

func readRecordForTest(t *testing.T, store *Store, conversationID string) *Record {
	t.Helper()
	rec, err := store.readRecord(store.paths(conversationID), conversationID)
	if err != nil {
		t.Fatalf("read record: %v", err)
	}
	if rec == nil {
		t.Fatal("no record on disk")
	}
	return rec
}

// ────────────────────────────────────────────────────────────────────────
// Send: the ordering invariant.
// ────────────────────────────────────────────────────────────────────────

// The whole of T-c in one assertion: at the instant the AEAD is called, the
// disk already says this position is being used.
func TestSendWritesTheIntentBeforeItEncrypts(t *testing.T) {
	store, _ := newTestStore(t)
	seedGroupState(t, store, testConvA, 4, 2, 7)

	var (
		pendingAtSeal *Position
		outboxAtSeal  int
	)
	cipher := &fakeCipher{}
	cipher.beforeAt = func() {
		rec := readRecordForTest(t, store, testConvA)
		pendingAtSeal = rec.PendingSend
		outboxAtSeal = len(rec.Outbox)
	}

	result, err := store.Send(testConvA, noWatermark, SendRequest{
		ClientMessageID: testClientA,
		Plaintext:       []byte("first"),
	}, cipher)
	if err != nil {
		t.Fatalf("send: %v", err)
	}

	if pendingAtSeal == nil {
		t.Fatal("the AEAD ran before the position was written down")
	}
	want := Position{Epoch: 4, SenderLeafIndex: 2, ContentType: ContentTypeApplication, Generation: 7}
	if *pendingAtSeal != want {
		t.Fatalf("intent on disk at the AEAD = %+v, want %+v", *pendingAtSeal, want)
	}
	if outboxAtSeal != 0 {
		t.Fatalf("the outbox already held %d entries when the AEAD ran", outboxAtSeal)
	}
	if result.Entry.Position != want || positionOf(t, result.Entry.Ciphertext) != want {
		t.Fatalf("the ciphertext did not land on the declared position: %+v / %q",
			result.Entry.Position, result.Entry.Ciphertext)
	}

	rec := readRecordForTest(t, store, testConvA)
	if rec.PendingSend != nil {
		t.Fatalf("the intent outlived the send: %+v", rec.PendingSend)
	}
	if string(rec.GroupState) != string(fakeState(4, 2, 8)) {
		t.Fatalf("the advanced state was not persisted: %q", rec.GroupState)
	}
}

// The declaration the sender puts on the wire has to name the position the
// ciphertext really occupies, because the receiver's check compares it against
// what the library derived keys from.
func TestSendDeclaresThePositionItEncryptsAt(t *testing.T) {
	store, _ := newTestStore(t)
	seedGroupState(t, store, testConvA, 1, 3, 9)
	cipher := &fakeCipher{}

	if _, err := store.Send(testConvA, noWatermark, SendRequest{
		ClientMessageID: testClientA,
		Plaintext:       []byte("declared"),
	}, cipher); err != nil {
		t.Fatalf("send: %v", err)
	}
	if got, want := string(cipher.lastAAD), "dragpass.chat.mls|1|a|3|9"; got != want {
		t.Fatalf("declaration = %q, want %q", got, want)
	}
}

// An intent with no ciphertext behind it is abandoned rather than retried. It
// cannot be known whether that position was consumed, and "maybe consumed" has
// to resolve to "consumed".
func TestSendBurnsAnUnfinishedPositionInsteadOfReusingIt(t *testing.T) {
	store, _ := newTestStore(t)
	seedGroupState(t, store, testConvA, 0, 0, 5)

	failing := &fakeCipher{sealErr: errors.New("the process would have died here")}
	if _, err := store.Send(testConvA, noWatermark, SendRequest{
		ClientMessageID: testClientA,
		Plaintext:       []byte("never made it"),
	}, failing); err == nil {
		t.Fatal("the failing send reported success")
	}

	stranded := readRecordForTest(t, store, testConvA)
	if stranded.PendingSend == nil || stranded.PendingSend.Generation != 5 {
		t.Fatalf("no intent was left behind: %+v", stranded.PendingSend)
	}

	next := &fakeCipher{}
	result, err := store.Send(testConvA, noWatermark, SendRequest{
		ClientMessageID: "55555555-5555-4555-8555-555555555555",
		Plaintext:       []byte("the one that got through"),
	}, next)
	if err != nil {
		t.Fatalf("send after the stranded intent: %v", err)
	}
	if next.burns != 1 {
		t.Fatalf("burned %d positions, want 1", next.burns)
	}
	used := positionOf(t, result.Entry.Ciphertext)
	if used.Generation != 6 {
		t.Fatalf("the ciphertext landed on generation %d; 5 was handed out twice", used.Generation)
	}
	if len(result.Burned) != 1 || result.Burned[0].Generation != 5 {
		t.Fatalf("the abandoned position was not reported: %+v", result.Burned)
	}
}

// The other direction of the same rule: a position the ratchet has already
// passed is not burned again, which would throw away a live generation on
// every restart.
func TestSendDoesNotBurnAPositionTheRatchetHasPassed(t *testing.T) {
	store, _ := newTestStore(t)
	seedGroupState(t, store, testConvA, 0, 0, 5)

	// Hand-build the shape a torn write could not produce but a future
	// refactor could: an intent behind the state it was written with.
	err := store.withConversation(testConvA, func(p convPaths) error {
		rec, anchor, err := store.loadChecked(p, testConvA, noWatermark)
		if err != nil {
			return err
		}
		rec.PendingSend = &Position{ContentType: ContentTypeApplication, Generation: 4}
		return store.commit(p, rec, rec.Generation, anchor)
	})
	if err != nil {
		t.Fatalf("seed the stale intent: %v", err)
	}

	cipher := &fakeCipher{}
	result, err := store.Send(testConvA, noWatermark, SendRequest{
		ClientMessageID: testClientA,
		Plaintext:       []byte("nothing to burn"),
	}, cipher)
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if cipher.burns != 0 {
		t.Fatalf("burned %d positions for an intent the ratchet had passed", cipher.burns)
	}
	if got := positionOf(t, result.Entry.Ciphertext).Generation; got != 5 {
		t.Fatalf("the ciphertext landed on generation %d, want 5", got)
	}
}

// An intent left over from an epoch the group has since left has nothing to
// burn: that secret tree is gone with the epoch. This is also the seam a
// pending Commit sits next to — when one is confirmed and the epoch rises, a
// stranded send intent from the old epoch has to be dropped rather than
// charged against the new epoch's chain.
func TestSendDropsAnIntentFromAnEpochTheGroupHasLeft(t *testing.T) {
	store, _ := newTestStore(t)
	seedGroupState(t, store, testConvA, 0, 0, 5)

	failing := &fakeCipher{sealErr: errors.New("died before the AEAD")}
	if _, err := store.Send(testConvA, noWatermark, SendRequest{
		ClientMessageID: testClientA,
		Plaintext:       []byte("never made it"),
	}, failing); err == nil {
		t.Fatal("the failing send reported success")
	}

	// A commit landed in between: new epoch, chain back to zero.
	seedGroupState(t, store, testConvA, 1, 0, 0)

	cipher := &fakeCipher{}
	result, err := store.Send(testConvA, noWatermark, SendRequest{
		ClientMessageID: "55555555-5555-4555-8555-555555555555",
		Plaintext:       []byte("first of the new epoch"),
	}, cipher)
	if err != nil {
		t.Fatalf("send in the new epoch: %v", err)
	}
	if cipher.burns != 0 || len(result.Burned) != 0 {
		t.Fatalf("burned %d positions of the new epoch for an intent of the old one", cipher.burns)
	}
	used := positionOf(t, result.Entry.Ciphertext)
	if used.Epoch != 1 || used.Generation != 0 {
		t.Fatalf("the new epoch's first send landed at %+v, want epoch 1 generation 0", used)
	}
	if readRecordForTest(t, store, testConvA).PendingSend != nil {
		t.Fatal("the stale intent survived")
	}
}

// The recovery loop has a bound, and hitting it refuses the send rather than
// grinding forward. A record and a library that disagree by more than one step
// is not a crash window, it is damage, and encrypting on top of it is the one
// thing that cannot be undone.
func TestSendRefusesWhenAnIntentCannotBeAbandonedWithinTheBound(t *testing.T) {
	store, _ := newTestStore(t)
	seedGroupState(t, store, testConvA, 0, 0, 0)

	err := store.withConversation(testConvA, func(p convPaths) error {
		rec, anchor, err := store.loadChecked(p, testConvA, noWatermark)
		if err != nil {
			return err
		}
		rec.PendingSend = &Position{
			ContentType: ContentTypeApplication,
			Generation:  uint64(maxBurnForward) + 1,
		}
		return store.commit(p, rec, rec.Generation, anchor)
	})
	if err != nil {
		t.Fatalf("seed the far intent: %v", err)
	}

	if _, err := store.Send(testConvA, noWatermark, SendRequest{
		ClientMessageID: testClientA,
		Plaintext:       []byte("should not be encrypted"),
	}, &fakeCipher{}); !errors.Is(err, ErrBurnForward) {
		t.Fatalf("send = %v, want ErrBurnForward", err)
	}
}

func TestSendRetransmissionReturnsTheStoredCiphertextWithoutEncrypting(t *testing.T) {
	store, _ := newTestStore(t)
	seedGroupState(t, store, testConvA, 0, 0, 0)

	first := &fakeCipher{}
	sent, err := store.Send(testConvA, noWatermark, SendRequest{
		ClientMessageID: testClientA,
		Plaintext:       []byte("say it once"),
	}, first)
	if err != nil {
		t.Fatalf("send: %v", err)
	}

	again := &fakeCipher{}
	resent, err := store.Send(testConvA, noWatermark, SendRequest{
		ClientMessageID: testClientA,
		Plaintext:       []byte("say it once"),
	}, again)
	if err != nil {
		t.Fatalf("resend: %v", err)
	}
	if again.seals != 0 {
		t.Fatalf("the retransmission encrypted again (%d seals)", again.seals)
	}
	if resent.Created || string(resent.Entry.Ciphertext) != string(sent.Entry.Ciphertext) {
		t.Fatalf("the retransmission differs: %q vs %q",
			resent.Entry.Ciphertext, sent.Entry.Ciphertext)
	}
	if got := readRecordForTest(t, store, testConvA).GroupState; string(got) != string(fakeState(0, 0, 1)) {
		t.Fatalf("the retransmission moved the chain: %q", got)
	}
}

func TestSendRefusesAnEpochTheRecordHasLeft(t *testing.T) {
	store, _ := newTestStore(t)
	seedGroupState(t, store, testConvA, 3, 0, 0)

	_, err := store.Send(testConvA, noWatermark, SendRequest{
		ClientMessageID: testClientA,
		Plaintext:       []byte("built for an older epoch"),
		ExpectedEpoch:   2,
	}, &fakeCipher{})
	if !errors.Is(err, ErrEpochStale) {
		t.Fatalf("send = %v, want ErrEpochStale", err)
	}
	if readRecordForTest(t, store, testConvA).PendingSend != nil {
		t.Fatal("a refused send left an intent behind")
	}
}

func TestSendNeedsAGroup(t *testing.T) {
	store, _ := newTestStore(t)
	_, err := store.Send(testConvA, noWatermark, SendRequest{
		ClientMessageID: testClientA,
		Plaintext:       []byte("no group yet"),
	}, &fakeCipher{})
	if !errors.Is(err, ErrNoGroupState) {
		t.Fatalf("send = %v, want ErrNoGroupState", err)
	}
}

// ────────────────────────────────────────────────────────────────────────
// Receive: atomic confirmation and the fail-closed generation check.
// ────────────────────────────────────────────────────────────────────────

type fakeInbound struct {
	opened Opened
	opens  int
	loaded bool

	// beforeState runs after the decrypt and before the confirmation is
	// serialized, which is the only place a crash could split the pair.
	beforeState func()
}

func (c *fakeInbound) Load(blob []byte) error {
	if len(blob) == 0 {
		return errors.New("fake inbound: empty state")
	}
	c.loaded = true
	return nil
}

func (c *fakeInbound) Open([]byte) (Opened, error) {
	c.opens++
	out := c.opened
	out.Plaintext = append([]byte(nil), c.opened.Plaintext...)
	return out, nil
}

func (c *fakeInbound) State() ([]byte, error) {
	if c.beforeState != nil {
		c.beforeState()
	}
	return fakeState(c.opened.Epoch, 0, 1), nil
}

func inbound(leaf uint32, generation uint32, plaintext string) *fakeInbound {
	known := generation
	position := Position{
		SenderLeafIndex: leaf,
		ContentType:     ContentTypeApplication,
		Generation:      uint64(generation),
	}
	return &fakeInbound{opened: Opened{
		SenderLeafIndex:   leaf,
		Application:       true,
		AuthenticatedData: position.declaration(),
		KeyGeneration:     &known,
		Plaintext:         []byte(plaintext),
	}}
}

func TestReceiveConfirmsTheStateAndTheHistoryInOneWrite(t *testing.T) {
	store, _ := newTestStore(t)
	seedGroupState(t, store, testConvA, 0, 0, 0)
	before := readRecordForTest(t, store, testConvA).Generation

	got, err := store.Receive(testConvA, noWatermark,
		ReceiveRequest{Seq: 11, Message: []byte("wire")}, inbound(3, 0, "hello"))
	if err != nil {
		t.Fatalf("receive: %v", err)
	}
	if string(got.Plaintext) != "hello" || !got.FirstDelivery || got.FromHistory {
		t.Fatalf("receive = %+v", got)
	}

	rec := readRecordForTest(t, store, testConvA)
	if rec.Generation != before+1 {
		t.Fatalf("the delivery took %d writes; the mark and the copy are not one write",
			rec.Generation-before)
	}
	if len(rec.Received) != 1 || len(rec.History) != 1 {
		t.Fatalf("mark=%d history=%d; want one of each", len(rec.Received), len(rec.History))
	}
	if rec.History[0].Seq != 11 {
		t.Fatalf("history keyed on %d, want 11", rec.History[0].Seq)
	}
}

// A re-read is served from the sealed copy. Nothing reaches MLS, because the
// key that opened it was consumed and deleted at the first delivery.
func TestReceiveServesARereadFromHistory(t *testing.T) {
	store, _ := newTestStore(t)
	seedGroupState(t, store, testConvA, 0, 0, 0)
	if _, err := store.Receive(testConvA, noWatermark,
		ReceiveRequest{Seq: 11, Message: []byte("wire")}, inbound(3, 0, "hello")); err != nil {
		t.Fatalf("first receive: %v", err)
	}
	generationAfterFirst := readRecordForTest(t, store, testConvA).Generation

	replay := inbound(3, 0, "hello")
	got, err := store.Receive(testConvA, noWatermark,
		ReceiveRequest{Seq: 11, Message: []byte("wire")}, replay)
	if err != nil {
		t.Fatalf("re-read: %v", err)
	}
	if replay.opens != 0 {
		t.Fatal("the re-read went back to the MLS layer")
	}
	if !got.FromHistory || string(got.Plaintext) != "hello" {
		t.Fatalf("re-read = %+v", got)
	}
	if readRecordForTest(t, store, testConvA).Generation != generationAfterFirst {
		t.Fatal("the re-read wrote to the record")
	}

	direct, err := store.ReadHistory(testConvA, noWatermark, 11)
	if err != nil || string(direct) != "hello" {
		t.Fatalf("ReadHistory = %q, %v", direct, err)
	}
	if _, err := store.ReadHistory(testConvA, noWatermark, 12); !errors.Is(err, ErrHistoryUnavailable) {
		t.Fatalf("ReadHistory on a missing seq = %v, want ErrHistoryUnavailable", err)
	}
}

// The sealed copy is a copy, and this says so: the plaintext is not in the
// bytes that go on the disk, and the only way back is the history key.
func TestHistoryIsStoredSealed(t *testing.T) {
	store, _ := newTestStore(t)
	seedGroupState(t, store, testConvA, 0, 0, 0)
	if _, err := store.Receive(testConvA, noWatermark,
		ReceiveRequest{Seq: 11, Message: []byte("wire")},
		inbound(3, 0, "회의는 14시로 옮깁니다")); err != nil {
		t.Fatalf("receive: %v", err)
	}

	entry := readRecordForTest(t, store, testConvA).History[0]
	if strings.Contains(string(entry.Ciphertext), "회의는") {
		t.Fatal("the history entry carries its plaintext")
	}
	if _, err := store.openHistory(testConvB, entry); err == nil {
		t.Fatal("a history entry opened under another conversation's binding")
	}
	tampered := entry
	tampered.Seq = 12
	if _, err := store.openHistory(testConvA, tampered); err == nil {
		t.Fatal("a history entry opened under a rewritten sequence")
	}
}

// Fail-closed, part one. The library answering None is not a zero and not a
// reason to skip the comparison; it ends the delivery.
func TestReceiveRefusesAMessageWhoseGenerationIsUnknown(t *testing.T) {
	store, _ := newTestStore(t)
	seedGroupState(t, store, testConvA, 0, 0, 0)
	before := readRecordForTest(t, store, testConvA).Generation

	cipher := inbound(3, 0, "should not be shown")
	cipher.opened.KeyGeneration = nil

	got, err := store.Receive(testConvA, noWatermark,
		ReceiveRequest{Seq: 11, Message: []byte("wire")}, cipher)
	if !errors.Is(err, ErrGenerationUnknown) {
		t.Fatalf("receive = %v, want ErrGenerationUnknown", err)
	}
	if got.Plaintext != nil {
		t.Fatalf("plaintext came back with the refusal: %q", got.Plaintext)
	}
	rec := readRecordForTest(t, store, testConvA)
	if rec.Generation != before || len(rec.Received) != 0 || len(rec.History) != 0 {
		t.Fatalf("a refused delivery was confirmed: %+v", rec)
	}
}

// Fail-closed, part two. A declaration that disagrees with the position the
// message actually occupies ends the delivery the same way.
func TestReceiveRefusesADeclarationThatDoesNotMatch(t *testing.T) {
	store, _ := newTestStore(t)
	seedGroupState(t, store, testConvA, 0, 0, 0)

	for name, mutate := range map[string]func(*fakeInbound){
		"generation": func(c *fakeInbound) {
			c.opened.AuthenticatedData = Position{
				SenderLeafIndex: 3, ContentType: ContentTypeApplication, Generation: 9,
			}.declaration()
		},
		"leaf": func(c *fakeInbound) {
			c.opened.AuthenticatedData = Position{
				SenderLeafIndex: 4, ContentType: ContentTypeApplication, Generation: 0,
			}.declaration()
		},
		"axis": func(c *fakeInbound) {
			c.opened.AuthenticatedData = Position{
				SenderLeafIndex: 3, ContentType: ContentTypeHandshake, Generation: 0,
			}.declaration()
		},
		"absent": func(c *fakeInbound) { c.opened.AuthenticatedData = nil },
		"garbage": func(c *fakeInbound) {
			c.opened.AuthenticatedData = []byte("dragpass.chat.mls|1|a|3")
		},
	} {
		t.Run(name, func(t *testing.T) {
			cipher := inbound(3, 0, "should not be shown")
			mutate(cipher)
			got, err := store.Receive(testConvA, noWatermark,
				ReceiveRequest{Seq: 11, Message: []byte("wire")}, cipher)
			if !errors.Is(err, ErrDeclarationMismatch) {
				t.Fatalf("receive = %v, want ErrDeclarationMismatch", err)
			}
			if got.Plaintext != nil {
				t.Fatalf("plaintext came back with the refusal: %q", got.Plaintext)
			}
		})
	}
}

// A gap in the sender's chain is what burn-forward leaves behind. It is an
// ordinary delivery on this side, not a missing message to wait for.
func TestReceiveAcceptsAGapLeftByBurnForward(t *testing.T) {
	store, _ := newTestStore(t)
	seedGroupState(t, store, testConvA, 0, 0, 0)

	if _, err := store.Receive(testConvA, noWatermark,
		ReceiveRequest{Seq: 1, Message: []byte("wire")}, inbound(3, 0, "before")); err != nil {
		t.Fatalf("receive at generation 0: %v", err)
	}
	// Generation 1 was burned by the sender and never became a ciphertext.
	got, err := store.Receive(testConvA, noWatermark,
		ReceiveRequest{Seq: 2, Message: []byte("wire")}, inbound(3, 2, "after"))
	if err != nil {
		t.Fatalf("receive across the gap: %v", err)
	}
	if !got.FirstDelivery || string(got.Plaintext) != "after" {
		t.Fatalf("receive across the gap = %+v", got)
	}
	if marks := readRecordForTest(t, store, testConvA).Received; len(marks) != 2 ||
		marks[0].Generation != 0 || marks[1].Generation != 2 {
		t.Fatalf("marks = %+v; want generations 0 and 2 with nothing invented at 1", marks)
	}
}

// Two members at the same epoch both start at generation 0. Four slots is what
// keeps the second one from being discarded as a repeat of the first.
func TestReceiveKeepsTwoSendersApartAtTheSameGeneration(t *testing.T) {
	store, _ := newTestStore(t)
	seedGroupState(t, store, testConvA, 0, 0, 0)

	if _, err := store.Receive(testConvA, noWatermark,
		ReceiveRequest{Seq: 1, Message: []byte("wire")}, inbound(3, 0, "from alice")); err != nil {
		t.Fatalf("first sender: %v", err)
	}
	got, err := store.Receive(testConvA, noWatermark,
		ReceiveRequest{Seq: 2, Message: []byte("wire")}, inbound(4, 0, "from bob"))
	if err != nil {
		t.Fatalf("second sender: %v", err)
	}
	if !got.FirstDelivery || string(got.Plaintext) != "from bob" {
		t.Fatalf("the second sender's generation 0 was discarded: %+v", got)
	}
}

func TestHistoryRingAndAgeBoundWhatTheRecordKeeps(t *testing.T) {
	store, _ := newTestStore(t)
	store.HistoryPolicy = HistoryPolicy{MaxEntries: 3}
	seedGroupState(t, store, testConvA, 0, 0, 0)

	for seq := range uint64(5) {
		if _, err := store.Receive(testConvA, noWatermark,
			ReceiveRequest{Seq: seq, Message: []byte("wire")},
			inbound(3, uint32(seq), fmt.Sprintf("message %d", seq)),
		); err != nil {
			t.Fatalf("receive %d: %v", seq, err)
		}
	}
	rec := readRecordForTest(t, store, testConvA)
	if len(rec.History) != 3 {
		t.Fatalf("history holds %d entries, want 3", len(rec.History))
	}
	if rec.History[0].Seq != 2 {
		t.Fatalf("the ring kept from seq %d, want 2", rec.History[0].Seq)
	}
	if _, err := store.ReadHistory(testConvA, noWatermark, 0); !errors.Is(err, ErrHistoryUnavailable) {
		t.Fatalf("an evicted entry = %v, want ErrHistoryUnavailable", err)
	}

	// MaxAge is the M4.6.1 seam. Zero applies no expiry; a value prunes on the
	// next write rather than on a timer, because the record is only ever
	// touched under the conversation lock.
	aged := Record{History: []HistoryEntry{{Seq: 1, StoredAt: time.Now().Add(-2 * time.Hour).Unix()}}}
	aged.appendHistory(HistoryEntry{Seq: 2, StoredAt: time.Now().Unix()},
		HistoryPolicy{MaxAge: time.Hour}, time.Now())
	if len(aged.History) != 1 || aged.History[0].Seq != 2 {
		t.Fatalf("MaxAge kept %+v", aged.History)
	}
}
