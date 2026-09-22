// anchor_test.go — the keyring anchor's two jobs: surviving the rename of the
// watermark it was storing, and judging only the axis a sender can actually
// advance.

package chatstate

import (
	"testing"

	"github.com/dragpass/keeper/config"
	"github.com/dragpass/keeper/internal/keystore/keychain"
)

// legacyAnchorJSON is a real anchor as 0.0.35–0.0.40 wrote one: one watermark
// counter under the old name, and no version field at all.
const legacyAnchorJSON = `{"generation":9,"reserved_before":12,"epoch":3,` +
	`"watermark_epoch":3,"watermark_next_index":7,"needs_rekey":false}`

func TestALegacyAnchorFoldsItsWatermarkIntoTheApplicationAxis(t *testing.T) {
	secrets := keychain.NewMemorySecretStore()
	const tag = "conversation-tag"
	if err := secrets.Set(config.Service, anchorAccount(tag), legacyAnchorJSON); err != nil {
		t.Fatal(err)
	}

	anchor, err := loadAnchor(secrets, tag)
	if err != nil {
		t.Fatalf("load legacy anchor: %v", err)
	}
	if anchor.Version != AnchorVersion {
		t.Fatalf("folded anchor version = %d, want %d", anchor.Version, AnchorVersion)
	}
	if anchor.WatermarkNextApplication != 7 {
		t.Fatalf("watermark_next_index landed on the application axis as %d, want 7",
			anchor.WatermarkNextApplication)
	}
	if anchor.WatermarkNextHandshake != 0 {
		t.Fatalf("the handshake axis invented a value: %d", anchor.WatermarkNextHandshake)
	}
	if anchor.Generation != 9 || anchor.ReservedBefore != 12 || anchor.Epoch != 3 {
		t.Fatalf("the rest of the legacy anchor did not survive: %+v", anchor)
	}

	// The fold is not cosmetic. A record this device rewound to position 5 is
	// caught only because the folded 7 is still there; read as zero, the axis
	// would quietly accept it.
	rewoundRecord := &Record{Generation: 9, NextIndex: 5, Epoch: 3}
	if !anchor.rewound(rewoundRecord, ServerWatermark{}) {
		t.Fatal("a folded legacy watermark stopped catching the rewind it was written for")
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

// The leaf a watermark is judged against comes out of the positions this
// device's own send path wrote, and only those name their ratchet. An entry
// that names none is not a device that sends from leaf 0; it is a device whose
// leaf this record has never learned.
func TestLocalLeafIsUnknownUntilTheSendPathWritesOne(t *testing.T) {
	store, _ := newTestStore(t)

	if _, known, err := store.LocalLeafIndex(testConvA); err != nil || known {
		t.Fatalf("a conversation with no record claimed a leaf: known=%v err=%v", known, err)
	}

	reservation, err := store.Reserve(testConvA, 1, noWatermark)
	if err != nil {
		t.Fatalf("reserve: %v", err)
	}
	if _, _, err := store.CommitOutbox(testConvA, noWatermark, sampleEntry(reservation.FirstChainIndex)); err != nil {
		t.Fatalf("commit outbox: %v", err)
	}
	if _, known, err := store.LocalLeafIndex(testConvA); err != nil || known {
		t.Fatalf("an axis-less outbox entry read as leaf 0: known=%v err=%v", known, err)
	}

	seedGroupState(t, store, testConvB, 0, 6, 0)
	if _, err := store.Send(testConvB, noWatermark, SendRequest{
		ClientMessageID: testClientA, Plaintext: []byte("hello"),
	}, &fakeCipher{}); err != nil {
		t.Fatalf("send: %v", err)
	}
	leaf, known, err := store.LocalLeafIndex(testConvB)
	if err != nil || !known || leaf != 6 {
		t.Fatalf("LocalLeafIndex after a send = %d, known=%v, err=%v; want 6, true", leaf, known, err)
	}
}
