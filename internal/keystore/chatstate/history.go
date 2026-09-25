// history.go — the local, sealed copy of a message that was already delivered.
//
// # Why it exists
//
// RFC 9420 §9.2 says a message key is consumed the moment a decrypt succeeds
// and must be deleted at once. So the window between "the receive state moved"
// and "the app has the plaintext" is not recoverable by retrying: the key is
// gone, the server's ciphertext is no longer openable by anyone here, and the
// message is lost. Design §8.4 closes that window by confirming the receive
// state and a sealed copy of the plaintext in the same write, and by serving a
// re-read from the copy instead of the wire.
//
// History is sealed, atomically confirmed with receive state, and retained for
// at most 90 days and 64 entries. Its sealing key is derived from the owner's
// seal key. Separate erasure controls and key placement remain undecided.
//
// # What the sealing key is and is not
//
// It is a third subkey of the owner's seal key, so it is separated from MLS
// message keys by construction, which is the condition §8.4 sets. It is *not*
// separately destroyable: derived from the same master, it dies with the seal
// key and not before. Whether it should be its own secret is M4.6.3.
//
// # Scope of what survives an erasure
//
// The history is inside the record file, so every statement store.go makes
// about the record covers it: it is replaced whole, a crash leaves the old
// copy or the new one, and purgeOwner removes the directory and then the seal
// key. Copies outside that reach are outside the erasure too — a backup taken
// before the purge still holds the sealed bytes, and the seal key is gone only
// from this keyring, not from a keychain backup that has it.

package chatstate

import (
	"cmp"
	"crypto/rand"
	"slices"
	"strconv"
	"strings"
	"time"
)

// DefaultHistoryMaxEntries bounds how many delivered messages one record
// carries. The record is rewritten whole on every change, so the ring also
// bounds the cost of each write. Age-based expiry is configured separately.
const DefaultHistoryMaxEntries = 64

// DefaultHistoryMaxAge removes sealed local copies after 90 days. The entry
// ring remains the tighter bound when it fills.
const DefaultHistoryMaxAge = 90 * 24 * time.Hour

const (
	historyAADDomain     = "dragpass.chat.state.history"
	sentHistoryAADDomain = "dragpass.chat.state.history.sent"
)

// HistoryPolicy is the part of the local history that is still open. Both
// fields are here so the values can be filled in when they are decided,
// without the shape of the receive path changing again.
type HistoryPolicy struct {
	// MaxEntries is the ring bound. Zero means DefaultHistoryMaxEntries.
	MaxEntries int

	// MaxAge drops entries older than this on write and read. Zero disables
	// age-based expiry; the entry limit still applies.
	MaxAge time.Duration
}

func (h HistoryPolicy) maxEntries() int {
	if h.MaxEntries <= 0 {
		return DefaultHistoryMaxEntries
	}
	return h.MaxEntries
}

// HistoryEntry is one delivered or sent message, sealed. Seq is the server's
// message sequence, which is what a re-read asks by.
type HistoryEntry struct {
	Seq      uint64 `json:"seq"`
	StoredAt int64  `json:"stored_at"`

	// ClientMessageID is set on a message this device sent, and only there.
	// mls-rs refuses to process a message from its own leaf
	// (CantProcessMessageFromSelf), so this copy is the only way the sender
	// ever reads its own message again. The server assigns the seq after the
	// send, so the entry is sealed under this id and Seq stays 0 until
	// MarkSent binds it.
	ClientMessageID string `json:"client_message_id,omitempty"`

	// Position is the one verifyDeclaration accepted at the first delivery,
	// written in the same replacement that confirmed it. A re-read has no
	// other source for who sent the message: the key that authenticated the
	// sender is gone, and the server's metadata is what MLS is here to not
	// need. It is bound into the AAD so it cannot be moved onto another
	// entry's plaintext.
	Position *Position `json:"position,omitempty"`

	// SenderAccountID and SenderDeviceID are the sending leaf's credential at
	// the first delivery, for the same reason Position is here: after that the
	// key and possibly the leaf are gone. Bound into the AAD with it.
	SenderAccountID string `json:"sender_account_id,omitempty"`
	SenderDeviceID  string `json:"sender_device_id,omitempty"`

	IV         []byte `json:"iv"`
	Ciphertext []byte `json:"ciphertext"`
}

// MaxOpenedSeqRanges bounds Record.OpenedSeqs. Seqs are opened mostly in
// order, so the set is one range plus a gap at each seq this device never
// opens (its own messages, its own Commits); the bound is reached only by a
// long conversation read out of order. A file-size bound, like the ring.
const MaxOpenedSeqRanges = 256

// SeqRange is the inclusive run [From, Through] of server seqs.
type SeqRange struct {
	From    uint64 `json:"from"`
	Through uint64 `json:"through"`
}

// markOpened records that MLS opened seq here, so a later re-read of it
// after the ring evicted its copy is answered as unavailable rather than
// handed to MLS a second time (receiveOne). The record is the right place:
// the mark lands in the same write as the state advance that consumed the key.
//
// On overflow the lowest gap is filled. The seqs in it then read as opened,
// so the direction of the error is a message shown as unavailable, never a
// consumed key handed back to MLS.
func (r *Record) markOpened(seq uint64, policy HistoryPolicy) {
	if seq == 0 {
		return
	}
	if len(r.OpenedSeqs) == 0 {
		if floor := r.legacyOpenedFloor(policy); floor > 0 {
			r.OpenedSeqs = []SeqRange{{From: 1, Through: floor}}
		}
	}
	ranges := append(r.OpenedSeqs, SeqRange{From: seq, Through: seq})
	slices.SortFunc(ranges, func(a, b SeqRange) int { return cmp.Compare(a.From, b.From) })
	merged := ranges[:1]
	for _, next := range ranges[1:] {
		last := &merged[len(merged)-1]
		if next.From <= last.Through+1 {
			last.Through = max(last.Through, next.Through)
			continue
		}
		merged = append(merged, next)
	}
	for len(merged) > MaxOpenedSeqRanges {
		merged[1].From = merged[0].From
		merged = merged[1:]
	}
	r.OpenedSeqs = merged
}

// opened reports whether MLS already opened seq on this device.
func (r *Record) opened(seq uint64, policy HistoryPolicy) bool {
	if len(r.OpenedSeqs) == 0 {
		return seq > 0 && seq <= r.legacyOpenedFloor(policy)
	}
	for _, run := range r.OpenedSeqs {
		if seq >= run.From && seq <= run.Through {
			return true
		}
	}
	return false
}

// legacyOpenedFloor stands in for OpenedSeqs in a record written before it
// existed: everything below the oldest delivered copy still held, and only
// when the ring is full, since a ring that never evicted still holds every
// message it was given. It is an inference and not a record — a seq below
// that copy that this device skipped reads as opened too — and it errs in the
// direction markOpened's overflow does: shown as unavailable, never handed
// back to MLS.
func (r *Record) legacyOpenedFloor(policy HistoryPolicy) uint64 {
	if len(r.History) < policy.maxEntries() {
		return 0
	}
	oldest := uint64(0)
	for _, e := range r.History {
		if e.ClientMessageID == "" && e.Seq > 0 && (oldest == 0 || e.Seq < oldest) {
			oldest = e.Seq
		}
	}
	if oldest == 0 {
		return 0
	}
	return oldest - 1
}

// findHistory never matches seq 0: that is a sent entry the server has not
// numbered yet, and no re-read can ask for it.
func (r *Record) findHistory(seq uint64) (HistoryEntry, bool) {
	if seq == 0 {
		return HistoryEntry{}, false
	}
	for _, e := range r.History {
		if e.Seq == seq {
			return e, true
		}
	}
	return HistoryEntry{}, false
}

func (r *Record) findSentHistory(clientMessageID string) (int, bool) {
	for i, e := range r.History {
		if e.ClientMessageID == clientMessageID {
			return i, true
		}
	}
	return 0, false
}

// appendHistory adds one entry, drops what the policy no longer keeps, and
// bounds the ring. Expiry also runs on reads; the conversation lock protects
// both paths.
func (r *Record) appendHistory(e HistoryEntry, policy HistoryPolicy, now time.Time) {
	r.pruneHistory(policy, now)
	kept := r.History[:0:0]
	for _, existing := range r.History {
		if e.replaces(existing) {
			continue
		}
		kept = append(kept, existing)
	}
	kept = append(kept, e)
	if limit := policy.maxEntries(); len(kept) > limit {
		kept = append([]HistoryEntry(nil), kept[len(kept)-limit:]...)
	}
	r.History = kept
}

func (r *Record) pruneHistory(policy HistoryPolicy, now time.Time) bool {
	kept := r.History[:0:0]
	cutoff := int64(0)
	if policy.MaxAge > 0 {
		cutoff = now.Add(-policy.MaxAge).Unix()
	}
	for _, existing := range r.History {
		if policy.MaxAge > 0 && existing.StoredAt < cutoff {
			continue
		}
		kept = append(kept, existing)
	}
	changed := len(kept) != len(r.History)
	r.History = kept
	return changed
}

// replaces reports whether e is a newer copy of the same message as existing.
// A sent entry is the same message by its client message id, a delivered one
// by its seq; an unbound sent entry's seq 0 names nothing.
func (e HistoryEntry) replaces(existing HistoryEntry) bool {
	if e.ClientMessageID != "" {
		return existing.ClientMessageID == e.ClientMessageID
	}
	return e.Seq != 0 && existing.Seq == e.Seq
}

// historyAAD binds a delivered entry to its seq and a sent entry to its client
// message id, under separate domains so neither can be read as the other.
//
// A sent entry's seq is not in its AAD because the seq does not exist when the
// entry is sealed, and resealing at MarkSent would put the plaintext through
// memory a second time to gain nothing: the record's own seal already covers
// Seq, and moving a bound seq onto another entry needs the seal key.
func historyAAD(ownerAccountID, conversationID string, e HistoryEntry, position Position, sender Sender) []byte {
	domain, key := historyAADDomain, strconv.FormatUint(e.Seq, 10)
	if e.ClientMessageID != "" {
		domain, key = sentHistoryAADDomain, e.ClientMessageID
	}
	return []byte(strings.Join([]string{
		domain,
		strconv.Itoa(SchemaVersion),
		ownerAccountID,
		conversationID,
		key,
		strconv.FormatUint(position.Epoch, 10),
		strconv.FormatUint(uint64(position.SenderLeafIndex), 10),
		string(position.ContentType),
		strconv.FormatUint(position.Generation, 10),
		sender.AccountID,
		sender.DeviceID,
	}, "|"))
}

// sealHistory wraps one delivered plaintext for storage. The caller still owns
// the plaintext buffer and still has to wipe it, and position must be the one
// the caller has just verified.
func (s *Store) sealHistory(
	conversationID string, seq uint64, position Position, sender Sender, plaintext []byte, now time.Time,
) (HistoryEntry, error) {
	return s.seal(conversationID, HistoryEntry{Seq: seq}, position, sender, plaintext, now)
}

// sealSentHistory wraps a plaintext this device is sending, at the position
// the send took, before the server has numbered it.
func (s *Store) sealSentHistory(
	conversationID, clientMessageID string, position Position, sender Sender, plaintext []byte, now time.Time,
) (HistoryEntry, error) {
	return s.seal(conversationID, HistoryEntry{ClientMessageID: clientMessageID}, position, sender, plaintext, now)
}

func (s *Store) seal(
	conversationID string, e HistoryEntry, position Position, sender Sender, plaintext []byte, now time.Time,
) (HistoryEntry, error) {
	gcm, err := newGCM(s.historyKey)
	if err != nil {
		return HistoryEntry{}, err
	}
	iv := make([]byte, ivBytes)
	if _, err := rand.Read(iv); err != nil {
		return HistoryEntry{}, err
	}
	e.StoredAt = now.Unix()
	e.Position = &position
	e.SenderAccountID, e.SenderDeviceID = sender.AccountID, sender.DeviceID
	e.IV = iv
	e.Ciphertext = gcm.Seal(nil, iv, plaintext, historyAAD(s.owner, conversationID, e, position, sender))
	return e, nil
}

// openHistory refuses an entry that carries no position rather than answering
// it with a zero one, which would name leaf 0 at epoch 0 as the sender. It is
// ErrHistoryUnavailable and not a sentinel of its own because the caller's
// answer has to be the same: this copy cannot say who sent it and nothing else
// may, so a distinct error would only invite a branch that asks the server.
func (s *Store) openHistory(conversationID string, e HistoryEntry) ([]byte, Position, error) {
	if e.Position == nil || !e.Position.ContentType.valid() {
		return nil, Position{}, ErrHistoryUnavailable
	}
	gcm, err := newGCM(s.historyKey)
	if err != nil {
		return nil, Position{}, err
	}
	if len(e.IV) != ivBytes {
		return nil, Position{}, errSealedRecordMalformed
	}
	plaintext, err := gcm.Open(nil, e.IV, e.Ciphertext,
		historyAAD(s.owner, conversationID, e, *e.Position, Sender{AccountID: e.SenderAccountID, DeviceID: e.SenderDeviceID}))
	if err != nil {
		return nil, Position{}, errSealedRecordMalformed
	}
	return plaintext, *e.Position, nil
}
