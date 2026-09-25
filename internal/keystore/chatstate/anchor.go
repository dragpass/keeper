// anchor.go — the keyring side of rollback detection.

package chatstate

import (
	"encoding/json"
	"errors"

	"github.com/dragpass/keeper/config"
	"github.com/dragpass/keeper/internal/keystore/keychain"
)

// AnchorVersion pins the anchor's field layout. Version 0 is an anchor written
// before the watermark was split per axis, and loadAnchor folds it rather than
// letting the renamed field read as zero.
const AnchorVersion = 1

// Anchor is what the state file is judged against. It is small enough for every
// platform keyring, and it is in the keyring precisely because the file is not:
// a backup that restores ~/Library/Application Support does not restore the
// login keychain along with it.
//
// It does not close the case where both are restored from the same moment. That
// is what ServerWatermark is for, and the two together still leave the "backup
// restore plus a cooperating server" gap the ADR records rather than hides.
type Anchor struct {
	// Version is the layout of the fields below. Absent in everything written
	// before the watermark gained its axes, which is what makes zero mean
	// "legacy" rather than "unset"; see loadAnchor.
	Version int `json:"version"`

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

	// The Watermark* fields remember the furthest the server has ever claimed
	// to have accepted from this sender. Kept monotonic here so a server that
	// later reports a lower position cannot talk this device into reusing a
	// chain position it already spent. The server is UNTRUSTED; what is
	// trusted is "the higher of the two, never the lower".
	//
	// Four slots because a sender's positions take four to name (Position),
	// and only one of them is compared: see rewound.
	WatermarkEpoch           uint64 `json:"watermark_epoch"`
	WatermarkLeafIndex       uint32 `json:"watermark_leaf_index"`
	WatermarkNextHandshake   uint64 `json:"watermark_next_handshake"`
	WatermarkNextApplication uint64 `json:"watermark_next_application"`

	// NeedsRekey latches once a rewind is seen. Nothing in this package clears
	// it: continuing on a rewound chain is the one thing the design must be
	// unable to do, so the only ways out are establishing a new epoch (the MLS
	// layer, not yet present) and Purge.
	NeedsRekey bool `json:"needs_rekey"`

	// RekeyCause is why NeedsRekey latched, written with it and never changed
	// afterwards: the first reason is the one that describes what happened.
	// Empty on an anchor latched before the field existed.
	RekeyCause RekeyCause `json:"rekey_cause,omitempty"`

	// RekeyEpoch and RekeyCommitter* say what an unauthorized_commit or a fork
	// latch was about: the epoch the refused or conflicting Commit produces, and
	// for an unauthorized one the leaf that committed it, as the group's own
	// tree names it. Written with the cause and never changed afterwards.
	RekeyEpoch              uint64 `json:"rekey_epoch,omitempty"`
	RekeyCommitterAccountID string `json:"rekey_committer_account_id,omitempty"`
	RekeyCommitterDeviceID  string `json:"rekey_committer_device_id,omitempty"`

	// SyncBlock is a received Commit this device refused and nothing has
	// superseded yet (syncblock.go). It is not a latch: a valid Commit for
	// its epoch clears it.
	SyncBlock *SyncBlock `json:"sync_block,omitempty"`
}

// RekeyCause says which check latched NeedsRekey. The recovery is the same for
// every cause; the distinction is for the person looking at the conversation,
// because a restored backup, a deleted file and a server claim are different
// events to explain.
type RekeyCause string

const (
	// RekeyCauseRollback — the file is behind the anchor: an older generation,
	// an older epoch, or a position the anchor never authorized.
	RekeyCauseRollback RekeyCause = "rollback_detected"

	// RekeyCauseStateMissing — the file is gone while the anchor says
	// positions were handed out.
	RekeyCauseStateMissing RekeyCause = "state_missing"

	// RekeyCauseWatermarkAhead — the server, or the anchor's copy of an
	// earlier server claim, says this device's own chain went further than
	// the file does.
	RekeyCauseWatermarkAhead RekeyCause = "watermark_ahead"

	// RekeyCauseAnchorUnreadable — the anchor itself could not be read. Not
	// stored: loadAnchor reports it on every read until the entry is replaced.
	RekeyCauseAnchorUnreadable RekeyCause = "anchor_unreadable"

	// RekeyCauseUnauthorizedCommit — a member's Commit carried an Add or a
	// Remove the authority rules do not allow (authority.go), and this device
	// refused to apply it. Every member that applied it is now on an epoch
	// this device will never reach, so from here the group is forked.
	RekeyCauseUnauthorizedCommit RekeyCause = "unauthorized_commit"

	// RekeyCauseFork — the server served, for an epoch this device already
	// confirmed, a Commit other than the one this device applied there.
	RekeyCauseFork RekeyCause = "fork"
)

// RekeyDetail is a latch cause and what it was about.
type RekeyDetail struct {
	Cause              RekeyCause
	Epoch              uint64
	CommitterAccountID string
	CommitterDeviceID  string
}

// RekeyLatchedError is ErrRekeyRequired from the operation that set the latch,
// carrying why. Every later operation answers the bare ErrRekeyRequired; the
// detail stays readable through Status.
type RekeyLatchedError struct{ Detail RekeyDetail }

func (e *RekeyLatchedError) Error() string {
	return ErrRekeyRequired.Error() + ": " + string(e.Detail.Cause)
}

func (e *RekeyLatchedError) Unwrap() error { return ErrRekeyRequired }

// ServerWatermark is the server's claim about how far this sender's chain has
// been accepted. It arrives inside the signed permit rather than as a free
// request field, so it cannot simply be left out by a caller that would rather
// not be checked.
//
// It is rollback detection that uses an honest, up-to-date server as a second
// witness: it catches a file and an anchor restored together from the past
// while the server's record is current. It does not catch a server that also
// returns a past value, and it does not catch sends that never reached the
// server. The metadata that buys it is the sender's account and leaf becoming
// server plaintext, which MLS otherwise keeps inside SenderData.
type ServerWatermark struct {
	Epoch                uint64
	LeafIndex            uint32
	NextHandshakeIndex   uint64
	NextApplicationIndex uint64

	// PendingRemovals rides in the same signed permit and is not a watermark:
	// it is the server's claim of which accounts left the organization and
	// still await a Remove Commit here (design §6.4.1). It can only add to
	// Record.RemovalLatch; see latch.go.
	PendingRemovals []string

	// PendingLeafReplacements rides in the same signed permit on the same
	// terms: the server's claim of which accounts a new device took over
	// (design M4.4). It can add to Record.LeafReplacementLatch or change the key
	// an entry waits for, never lift one.
	PendingLeafReplacements []LeafReplacement

	// PendingDeviceRevocations rides in the same signed permit on the same
	// terms: the server's claim of which device leaves their accounts revoked
	// (design Q13). It can only add to Record.DeviceRevokeLatch.
	PendingDeviceRevocations []DeviceRef
}

// HasAccepted reports whether the server has ever taken a position from this
// sender. Until it has, LeafIndex describes no chain and must not be compared
// against one.
func (w ServerWatermark) HasAccepted() bool {
	return w.NextHandshakeIndex != 0 || w.NextApplicationIndex != 0
}

func anchorAccount(conversationTag string) string {
	return config.ChatStateAnchorPrefix + conversationTag
}

// legacyAnchor reads the one field version 0 spelled differently. Decoded
// separately rather than kept on Anchor so the current layout carries no field
// that must be remembered to stay empty.
type legacyAnchor struct {
	WatermarkNextIndex uint64 `json:"watermark_next_index"`
}

func loadAnchor(secrets keychain.SecretStore, conversationTag string) (Anchor, error) {
	value, err := secrets.Get(config.Service, anchorAccount(conversationTag))
	if err != nil {
		if errors.Is(err, keychain.ErrSecretNotFound) {
			return Anchor{Version: AnchorVersion}, nil
		}
		return Anchor{}, err
	}
	var a Anchor
	if err := json.Unmarshal([]byte(value), &a); err != nil {
		// An unreadable anchor is treated as a rewind rather than as an empty
		// one: "cannot tell how far this chain got" must never resolve to
		// "start again from zero".
		return Anchor{Version: AnchorVersion, NeedsRekey: true, RekeyCause: RekeyCauseAnchorUnreadable}, nil
	}
	if a.Version == 0 {
		// The single axis a version-0 anchor held is the application one. Not
		// a guess: encrypt_control_messages is pinned false, so a sender has
		// never advanced its handshake ratchet (see rewound). Folding it into
		// the other axis, or dropping it because the field was renamed, would
		// both lose the only position this anchor ever knew about.
		var legacy legacyAnchor
		if err := json.Unmarshal([]byte(value), &legacy); err != nil {
			return Anchor{Version: AnchorVersion, NeedsRekey: true, RekeyCause: RekeyCauseAnchorUnreadable}, nil
		}
		a.WatermarkNextApplication = legacy.WatermarkNextIndex
		a.Version = AnchorVersion
	}
	return a, nil
}

func saveAnchor(secrets keychain.SecretStore, conversationTag string, a Anchor) error {
	a.Version = AnchorVersion
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

// rewound reports whether the record has fallen behind either axis: the
// local one (rewoundLocally) or the watermark (watermarkAhead).
func (a Anchor) rewound(rec *Record, wm ServerWatermark) bool {
	return a.rewoundLocally(rec) || a.watermarkAhead(rec, wm)
}

// rewoundLocally is the half of the judgement that needs nothing but the file
// and the keyring:
//
//   - rec.Generation < a.Generation: the file is older than what was committed.
//     The reverse (file ahead of the anchor) is the ordinary crash window
//     between the file rename and the anchor write, and is accepted: those
//     positions are already spent in the file, which is the safe direction.
//   - rec.NextIndex > a.ReservedBefore: the file claims positions the anchor
//     never authorized.
//   - rec.Epoch < a.Epoch: the file is from before an epoch this device
//     already confirmed.
func (a Anchor) rewoundLocally(rec *Record) bool {
	return rec.Generation < a.Generation ||
		rec.NextIndex > a.ReservedBefore ||
		rec.Epoch < a.Epoch
}

// watermarkAhead reports whether the server, or the anchor's copy of an
// earlier server claim, has accepted a position this file does not know it
// sent. A watermark that is not this device's chain (Record.ownsChain) takes
// no part.
//
// Only the application axis of the watermark is compared, and the handshake one
// is carried without being looked at. encrypt_control_messages is pinned false,
// so a Commit goes out as a PublicMessage and consumes no ratchet position —
// mls.Cipher.Peek hard-codes ContentTypeApplication for that reason. This
// device therefore cannot advance its handshake generation at all, and a
// non-zero handshake watermark compared against a record that structurally
// cannot match it would latch the conversation on a value it could never reach.
// A server inflating that slot is an availability attack that learns no
// plaintext, which is the position design §7.4's table already takes. The slot
// is kept because flipping that setting brings the axis back.
func (a Anchor) watermarkAhead(rec *Record, wm ServerWatermark) bool {
	var epoch, nextIndex uint64
	if rec.ownsChain(a.WatermarkEpoch, a.WatermarkLeafIndex, a.hasWatermark()) {
		epoch, nextIndex = a.WatermarkEpoch, a.WatermarkNextApplication
	}
	if rec.ownsChain(wm.Epoch, wm.LeafIndex, wm.HasAccepted()) &&
		(wm.Epoch > epoch || (wm.Epoch == epoch && wm.NextApplicationIndex > nextIndex)) {
		epoch, nextIndex = wm.Epoch, wm.NextApplicationIndex
	}
	if epoch > rec.Epoch {
		return true
	}
	return epoch == rec.Epoch && nextIndex > rec.NextIndex
}

func (a Anchor) hasWatermark() bool {
	return a.WatermarkNextHandshake != 0 || a.WatermarkNextApplication != 0
}

// advancedBy is withWatermark for a watermark judged against rec: one that is
// not this device's chain moves nothing, and a stored watermark that is not
// this device's chain is replaced rather than merged into. The second case is
// an anchor that took another leaf's claim before the leaf was known here;
// taking the higher slot of two chains would leave neither one protected.
func (a Anchor) advancedBy(rec *Record, wm ServerWatermark) Anchor {
	if !rec.ownsChain(wm.Epoch, wm.LeafIndex, wm.HasAccepted()) {
		return a
	}
	if !rec.ownsChain(a.WatermarkEpoch, a.WatermarkLeafIndex, a.hasWatermark()) {
		a.WatermarkEpoch, a.WatermarkLeafIndex = 0, 0
		a.WatermarkNextHandshake, a.WatermarkNextApplication = 0, 0
	}
	return a.withWatermark(wm)
}

// withWatermark returns the anchor advanced to the higher of its own watermark
// and the server's. Only ever forward, on every slot.
//
// A newer epoch replaces the index slots rather than raising them, because a
// generation counts steps along one epoch's ratchet: carrying the old epoch's
// higher number into the new one would compare a position against a chain that
// never held it. Within one epoch the two axes move independently, so each
// takes the higher of the two on its own.
func (a Anchor) withWatermark(wm ServerWatermark) Anchor {
	switch {
	case wm.Epoch > a.WatermarkEpoch:
		a.WatermarkEpoch = wm.Epoch
		a.WatermarkLeafIndex = wm.LeafIndex
		a.WatermarkNextHandshake = wm.NextHandshakeIndex
		a.WatermarkNextApplication = wm.NextApplicationIndex
	case wm.Epoch == a.WatermarkEpoch:
		a.WatermarkLeafIndex = max(a.WatermarkLeafIndex, wm.LeafIndex)
		a.WatermarkNextHandshake = max(a.WatermarkNextHandshake, wm.NextHandshakeIndex)
		a.WatermarkNextApplication = max(a.WatermarkNextApplication, wm.NextApplicationIndex)
	}
	return a
}
