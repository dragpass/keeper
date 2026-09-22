// anchor.go — the keyring side of rollback detection.

package chatstate

import (
	"encoding/json"
	"errors"

	"github.com/dragpass/keeper/config"
	"github.com/dragpass/keeper/internal/keystore/keychain"
)

// Anchor is what the state file is judged against. It is small enough for every
// platform keyring, and it is in the keyring precisely because the file is not:
// a backup that restores ~/Library/Application Support does not restore the
// login keychain along with it.
//
// It does not close the case where both are restored from the same moment. That
// is what ServerWatermark is for, and the two together still leave the "backup
// restore plus a cooperating server" gap the ADR records rather than hides.
type Anchor struct {
	// Generation is the highest generation this device ever committed. A file
	// below it is a restored copy.
	Generation uint64 `json:"generation"`

	// ReservedBefore is the exclusive ceiling of the chain positions the anchor
	// has authorized: [0, ReservedBefore). It is raised before the file
	// advances into it, so a file whose NextIndex sits above it was either
	// forged or is being judged by a rewound anchor. Holding a ceiling rather
	// than a mirror of NextIndex is also what lets a future block reservation
	// amortize the keyring writes without changing this check.
	ReservedBefore uint64 `json:"reserved_before"`

	Epoch uint64 `json:"epoch"`

	// WatermarkEpoch / WatermarkNextIndex remember the furthest the server has
	// ever claimed to have accepted from this sender. Kept monotonic here so a
	// server that later reports a lower position cannot talk this device into
	// reusing a chain position it already spent. The server is UNTRUSTED; what
	// is trusted is "the higher of the two, never the lower".
	WatermarkEpoch     uint64 `json:"watermark_epoch"`
	WatermarkNextIndex uint64 `json:"watermark_next_index"`

	// NeedsRekey latches once a rewind is seen. Nothing in this package clears
	// it: continuing on a rewound chain is the one thing the design must be
	// unable to do, so the only ways out are establishing a new epoch (the MLS
	// layer, not yet present) and Purge.
	NeedsRekey bool `json:"needs_rekey"`
}

// ServerWatermark is the server's claim about how far this sender's chain has
// been accepted. It arrives inside the signed permit rather than as a free
// request field, so it cannot simply be left out by a caller that would rather
// not be checked.
type ServerWatermark struct {
	Epoch     uint64
	NextIndex uint64
}

func anchorAccount(conversationTag string) string {
	return config.ChatStateAnchorPrefix + conversationTag
}

func loadAnchor(secrets keychain.SecretStore, conversationTag string) (Anchor, error) {
	value, err := secrets.Get(config.Service, anchorAccount(conversationTag))
	if err != nil {
		if errors.Is(err, keychain.ErrSecretNotFound) {
			return Anchor{}, nil
		}
		return Anchor{}, err
	}
	var a Anchor
	if err := json.Unmarshal([]byte(value), &a); err != nil {
		// An unreadable anchor is treated as a rewind rather than as an empty
		// one: "cannot tell how far this chain got" must never resolve to
		// "start again from zero".
		return Anchor{NeedsRekey: true}, nil
	}
	return a, nil
}

func saveAnchor(secrets keychain.SecretStore, conversationTag string, a Anchor) error {
	raw, err := json.Marshal(a)
	if err != nil {
		return err
	}
	return secrets.Set(config.Service, anchorAccount(conversationTag), string(raw))
}

func deleteAnchor(secrets keychain.SecretStore, conversationTag string) error {
	err := secrets.Delete(config.Service, anchorAccount(conversationTag))
	if err != nil && errors.Is(err, keychain.ErrSecretNotFound) {
		return nil
	}
	return err
}

// rewound reports whether the record has fallen behind either axis.
//
//   - rec.Generation < a.Generation: the file is older than what was committed.
//     The reverse (file ahead of the anchor) is the ordinary crash window
//     between the file rename and the anchor write, and is accepted: those
//     positions are already spent in the file, which is the safe direction.
//   - rec.NextIndex > a.ReservedBefore: the file claims positions the anchor
//     never authorized.
//   - the server has accepted a position this file does not know it sent.
func (a Anchor) rewound(rec *Record, wm ServerWatermark) bool {
	if rec.Generation < a.Generation {
		return true
	}
	if rec.NextIndex > a.ReservedBefore {
		return true
	}
	if rec.Epoch < a.Epoch {
		return true
	}
	epoch, nextIndex := a.WatermarkEpoch, a.WatermarkNextIndex
	if wm.Epoch > epoch || (wm.Epoch == epoch && wm.NextIndex > nextIndex) {
		epoch, nextIndex = wm.Epoch, wm.NextIndex
	}
	if epoch > rec.Epoch {
		return true
	}
	return epoch == rec.Epoch && nextIndex > rec.NextIndex
}

// withWatermark returns the anchor advanced to the higher of its own watermark
// and the server's. Only ever forward.
func (a Anchor) withWatermark(wm ServerWatermark) Anchor {
	if wm.Epoch > a.WatermarkEpoch ||
		(wm.Epoch == a.WatermarkEpoch && wm.NextIndex > a.WatermarkNextIndex) {
		a.WatermarkEpoch, a.WatermarkNextIndex = wm.Epoch, wm.NextIndex
	}
	return a
}
