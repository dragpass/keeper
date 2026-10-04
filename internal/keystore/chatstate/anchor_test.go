// anchor_test.go — the keyring anchor's two jobs: refusing a layout it does
// not know, and judging only the axis a sender can actually advance.

package chatstate

import (
	"bytes"
	"errors"
	"testing"

	"github.com/dragpass/keeper/config"
	"github.com/dragpass/keeper/internal/keystore/testdouble"
)

// retiredAnchorJSON is an anchor as unreleased development builds wrote one:
// one watermark counter under an old name, and no version field at all.
const retiredAnchorJSON = `{"generation":9,"reserved_before":12,"epoch":3,` +
	`"watermark_epoch":3,"watermark_next_index":7,"needs_rekey":false}`

// rewound reports whether the record has fallen behind either axis: the
// local one (rewoundLocally) or the watermark (watermarkAhead).
func (a Anchor) rewound(rec *Record, wm ServerWatermark) bool {
	return a.rewoundLocally(rec) || a.watermarkAhead(rec, wm)
}

// The unversioned anchor of unreleased development builds kept one watermark
// under an old name. It is not folded into the current layout; it reads as an
// unreadable anchor, which latches a rekey rather than starting from zero.
func TestARetiredUnversionedAnchorIsUnreadable(t *testing.T) {
	secrets := testdouble.NewMemorySecretStore()
	const tag = "conversation-tag"
	if err := secrets.Set(config.Service, anchorAccount(tag), retiredAnchorJSON); err != nil {
		t.Fatal(err)
	}

	anchor, err := loadAnchor(secrets, tag)
	if err != nil {
		t.Fatalf("load retired anchor: %v", err)
	}
	if !anchor.NeedsRekey || anchor.RekeyCause != RekeyCauseAnchorUnreadable {
		t.Fatalf("retired anchor = %+v, want an unreadable-anchor rekey", anchor)
	}
}

func TestTheApplicationAxisCatchesAServerAheadOfTheFile(t *testing.T) {
	anchor := Anchor{Version: AnchorVersion, Generation: 4, ReservedBefore: 6, Epoch: 2}
	record := &Record{Generation: 4, NextIndex: 5, Epoch: 2}

	for name, tc := range map[string]struct {
		watermark ServerWatermark
		rewound   bool
	}{
		"server ahead of the file":   {ServerWatermark{Epoch: 2, NextApplicationIndex: 6}, true},
		"server behind the file":     {ServerWatermark{Epoch: 2, NextApplicationIndex: 3}, false},
		"server level with the file": {ServerWatermark{Epoch: 2, NextApplicationIndex: 5}, false},
	} {
		if got := anchor.rewound(record, tc.watermark); got != tc.rewound {
			t.Fatalf("%s: rewound = %v, want %v", name, got, tc.rewound)
		}
	}
}

// encrypt_control_messages is pinned false, so a Commit leaves as a
// PublicMessage and this device never advances its handshake generation —
// mls.Cipher.Peek hard-codes the application axis for that reason. A handshake
// watermark compared against a record that structurally cannot match it would
// latch the conversation on a number it could never reach, so the slot is
// carried and not compared.
func TestAHandshakeWatermarkIsCarriedRatherThanCompared(t *testing.T) {
	anchor := Anchor{Version: AnchorVersion, Generation: 4, ReservedBefore: 6, Epoch: 2}
	record := &Record{Generation: 4, NextIndex: 5, Epoch: 2}
	watermark := ServerWatermark{Epoch: 2, NextHandshakeIndex: 99}

	if anchor.rewound(record, watermark) {
		t.Fatal("a handshake watermark latched a conversation that cannot advance that axis")
	}
	if got := anchor.withWatermark(watermark).WatermarkNextHandshake; got != 99 {
		t.Fatalf("the handshake slot was dropped instead of carried: %d", got)
	}
}

func TestWithWatermarkNeverLowersASlot(t *testing.T) {
	anchor := Anchor{
		Version:                  AnchorVersion,
		WatermarkEpoch:           4,
		WatermarkLeafIndex:       3,
		WatermarkNextHandshake:   8,
		WatermarkNextApplication: 11,
	}

	lower := anchor.withWatermark(ServerWatermark{
		Epoch: 4, LeafIndex: 1, NextHandshakeIndex: 2, NextApplicationIndex: 5,
	})
	if lower != anchor {
		t.Fatalf("a server reporting less moved the anchor: %+v", lower)
	}

	higher := anchor.withWatermark(ServerWatermark{
		Epoch: 4, LeafIndex: 3, NextHandshakeIndex: 8, NextApplicationIndex: 20,
	})
	if higher.WatermarkNextApplication != 20 || higher.WatermarkNextHandshake != 8 {
		t.Fatalf("one axis moving dragged the other: %+v", higher)
	}

	// A newer epoch replaces the counters instead of keeping the old epoch's
	// higher ones: a generation counts steps along one epoch's ratchet.
	next := anchor.withWatermark(ServerWatermark{
		Epoch: 5, LeafIndex: 3, NextHandshakeIndex: 0, NextApplicationIndex: 1,
	})
	if next.WatermarkEpoch != 5 || next.WatermarkNextApplication != 1 ||
		next.WatermarkNextHandshake != 0 {
		t.Fatalf("a new epoch carried the old epoch's counters: %+v", next)
	}
}

// ────────────────────────────────────────────────────────────────────────
// The sending chain the watermark is compared against
// ────────────────────────────────────────────────────────────────────────

// sendOnce puts one message through the MLS send path and returns the
// watermark ariadne would record for it: the next free position on the axis
// that send declared.
func sendOnce(t *testing.T, store *Store, conversationID, clientMessageID string) ServerWatermark {
	t.Helper()
	sent, err := store.Send(conversationID, noWatermark, SendRequest{
		ClientMessageID: clientMessageID, Plaintext: []byte("payload"),
	}, &fakeCipher{})
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	return ServerWatermark{
		Epoch:                sent.Entry.Position.Epoch,
		LeafIndex:            sent.Entry.Position.SenderLeafIndex,
		NextApplicationIndex: sent.Entry.Position.Generation + 1,
	}
}

// The regression this test exists for. The MLS send path did not record the
// position it took, so NextIndex stayed 0 while the server counted upward. A
// watermark exists only once a send declared a position, and only this path
// declares one, so "the server has a watermark at all" and "NextIndex is still
// 0" were the same moment: the axis latched on first use, every time, rather
// than eventually under some unlucky ordering.
func TestTheWatermarkForThePositionJustSentDoesNotLatch(t *testing.T) {
	store, _ := newTestStore(t)
	seedGroupState(t, store, testConvA, 4, 2, 0)
	recorded := sendOnce(t, store, testConvA, testClientA)

	if _, err := store.ReadOutbox(testConvA, recorded, testClientA); err != nil {
		t.Fatalf("the watermark for the position just sent latched the conversation: %v", err)
	}
}

// The axis has to keep detecting, not merely stop latching falsely: a server
// holding a position this device never sent is the whole case axis 2 is for.
func TestAWatermarkOnePositionAheadOfTheLastSendStillLatches(t *testing.T) {
	store, _ := newTestStore(t)
	seedGroupState(t, store, testConvA, 4, 2, 0)
	ahead := sendOnce(t, store, testConvA, testClientA)
	ahead.NextApplicationIndex++

	if _, err := store.ReadOutbox(testConvA, ahead, testClientA); !errors.Is(err, ErrRekeyRequired) {
		t.Fatalf("a watermark ahead of the last send = %v, want ErrRekeyRequired", err)
	}
}

// Both counters belong to one epoch's ratchet, so both restart when the chain
// enters a new one. The assertion that matters is the last: carried across,
// epoch 4's count of three would swallow every position below it in epoch 5
// and the axis would go quiet instead of latching.
func TestAnEpochAdvanceRestartsBothChainCounters(t *testing.T) {
	store, _ := newTestStore(t)
	seedGroupState(t, store, testConvA, 4, 2, 0)
	for i := range 3 {
		sendOnce(t, store, testConvA, clientID(i))
	}
	if got := readRecordForTest(t, store, testConvA).NextIndex; got != 3 {
		t.Fatalf("NextIndex after three sends = %d, want 3", got)
	}
	if got := anchorForTest(t, store, testConvA).ReservedBefore; got != 3 {
		t.Fatalf("ReservedBefore after three sends = %d, want 3", got)
	}

	// Somebody else's Commit carries the group to epoch 5.
	arrival := inbound(3, 0, "hello")
	arrival.opened.Epoch = 5
	if _, err := store.Receive(testConvA, noWatermark,
		ReceiveRequest{Seq: 11, Message: []byte("wire")}, arrival); err != nil {
		t.Fatalf("receive: %v", err)
	}
	rec := readRecordForTest(t, store, testConvA)
	anchor := anchorForTest(t, store, testConvA)
	if rec.Epoch != 5 || rec.NextIndex != 0 {
		t.Fatalf("record after the epoch advance = epoch %d, NextIndex %d; want 5, 0",
			rec.Epoch, rec.NextIndex)
	}
	if anchor.Epoch != 5 || anchor.ReservedBefore != 0 {
		t.Fatalf("anchor after the epoch advance = epoch %d, ReservedBefore %d; want 5, 0",
			anchor.Epoch, anchor.ReservedBefore)
	}

	// One send on the new chain, and the watermark for it compares against the
	// new epoch's generation rather than the old epoch's count.
	recorded := sendOnce(t, store, testConvA, clientID(4))
	if recorded.Epoch != 5 {
		t.Fatalf("the send after the advance was on epoch %d, want 5", recorded.Epoch)
	}
	if _, err := store.ReadOutbox(testConvA, recorded, clientID(4)); err != nil {
		t.Fatalf("the watermark for the first send of a new epoch latched: %v", err)
	}
	ahead := recorded
	ahead.NextApplicationIndex++
	if _, err := store.ReadOutbox(testConvA, ahead, clientID(4)); !errors.Is(err, ErrRekeyRequired) {
		t.Fatalf("the axis stopped detecting in the new epoch: %v", err)
	}
}

// Resetting the counters at the boundary takes nothing away, because the epoch
// comparison catches a record from before it on its own. The first case is the
// one that proves it: with both counters at zero on each side, `rec.Epoch <
// a.Epoch` is the only check left that can fire.
func TestARewindAcrossAnEpochBoundaryIsStillCaught(t *testing.T) {
	anchor := Anchor{Version: AnchorVersion, Generation: 9, Epoch: 5, ReservedBefore: 0}
	for name, rec := range map[string]*Record{
		"nothing spent in the old epoch":   {Generation: 9, Epoch: 4, NextIndex: 0},
		"positions spent in the old epoch": {Generation: 9, Epoch: 4, NextIndex: 7},
	} {
		if !anchor.rewound(rec, ServerWatermark{}) {
			t.Fatalf("%s: a record from before the epoch boundary was accepted", name)
		}
	}
}

// Send raising the shared counter is exactly what makes a generation it
// already spent look handed-out to the pre-MLS path, and the number is all the
// two can collide on, since only Send names an axis.
func TestTheLegacyPathCannotTakeAGenerationTheSendPathSealed(t *testing.T) {
	store, _ := newTestStore(t)
	seedGroupState(t, store, testConvA, 0, 2, 0)
	sendOnce(t, store, testConvA, testClientA)

	clash := OutboxEntry{
		ClientMessageID: clientID(9),
		Position:        Position{Epoch: 0, Generation: 0},
		IV:              bytes.Repeat([]byte{7}, ivBytes),
		Ciphertext:      []byte("a second ciphertext at one position"),
	}
	if _, _, err := store.CommitOutbox(testConvA, noWatermark, clash); !errors.Is(err, ErrPositionTaken) {
		t.Fatalf("commit outbox onto a sealed generation = %v, want ErrPositionTaken", err)
	}
}
