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
// # What this file does and does not settle
//
// Settled by §8.4's conditions: the copy is sealed, never written as
// plaintext, keyed by something other than an MLS message key, and confirmed
// atomically with the receive state. It lives in the Record because that is
// what makes the last one true — a separate file would be a second atomicity
// unit, which ADR §3.5 rejected for the group state for the same reason.
//
// Not settled here, and deliberately not given a default that reads like an
// answer:
//
//   - M4.6.1, how long a message is kept. HistoryPolicy.MaxAge is the seam and
//     is zero until somebody names a number.
//   - M4.6.2, what else erases it besides expiry.
//   - M4.6.3, whether the record is the right home and whether the sealing key
//     should be its own keyring entry rather than derived from the owner's
//     seal key.
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
	"crypto/rand"
	"strconv"
	"strings"
	"time"
)

// DefaultHistoryMaxEntries bounds how many delivered messages one record
// carries. It is a file-size bound and nothing else: the record is rewritten
// whole on every change, so the ring is what stops one conversation's file
// from growing until each write costs a megabyte. It is not a retention
// period and must not be quoted as one; that number is M4.6.1's.
const DefaultHistoryMaxEntries = 64

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

	// MaxAge drops entries older than this at the next write. Zero applies no
	// age-based expiry, which is the honest state of an undecided parameter
	// and not a promise that history is kept forever: the ring still evicts,
	// and M4.6.2 may add erasers this field knows nothing about.
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
// bounds the ring. Expiry runs on write rather than on a timer because this
// package has no thread of its own: the record is only ever touched under the
// conversation lock, and that is the only moment an entry can be removed
// without racing a reader.
func (r *Record) appendHistory(e HistoryEntry, policy HistoryPolicy, now time.Time) {
	kept := r.History[:0:0]
	cutoff := int64(0)
	if policy.MaxAge > 0 {
		cutoff = now.Add(-policy.MaxAge).Unix()
	}
	for _, existing := range r.History {
		if existing.StoredAt < cutoff || e.replaces(existing) {
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
