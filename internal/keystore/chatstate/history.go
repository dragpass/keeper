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

const historyAADDomain = "dragpass.chat.state.history"

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

// HistoryEntry is one delivered message, sealed. Seq is the server's message
// sequence, which is what a re-read asks by.
type HistoryEntry struct {
	Seq        uint64 `json:"seq"`
	StoredAt   int64  `json:"stored_at"`
	IV         []byte `json:"iv"`
	Ciphertext []byte `json:"ciphertext"`
}

func (r *Record) findHistory(seq uint64) (HistoryEntry, bool) {
	for _, e := range r.History {
		if e.Seq == seq {
			return e, true
		}
	}
	return HistoryEntry{}, false
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
		if existing.Seq == e.Seq || existing.StoredAt < cutoff {
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

func historyAAD(ownerAccountID, conversationID string, seq uint64) []byte {
	return []byte(strings.Join([]string{
		historyAADDomain,
		strconv.Itoa(SchemaVersion),
		ownerAccountID,
		conversationID,
		strconv.FormatUint(seq, 10),
	}, "|"))
}

// sealHistory wraps one plaintext for storage. The caller still owns the
// plaintext buffer and still has to wipe it.
func (s *Store) sealHistory(conversationID string, seq uint64, plaintext []byte, now time.Time) (HistoryEntry, error) {
	gcm, err := newGCM(s.historyKey)
	if err != nil {
		return HistoryEntry{}, err
	}
	iv := make([]byte, ivBytes)
	if _, err := rand.Read(iv); err != nil {
		return HistoryEntry{}, err
	}
	return HistoryEntry{
		Seq:        seq,
		StoredAt:   now.Unix(),
		IV:         iv,
		Ciphertext: gcm.Seal(nil, iv, plaintext, historyAAD(s.owner, conversationID, seq)),
	}, nil
}

func (s *Store) openHistory(conversationID string, e HistoryEntry) ([]byte, error) {
	gcm, err := newGCM(s.historyKey)
	if err != nil {
		return nil, err
	}
	if len(e.IV) != ivBytes {
		return nil, errSealedRecordMalformed
	}
	plaintext, err := gcm.Open(nil, e.IV, e.Ciphertext, historyAAD(s.owner, conversationID, e.Seq))
	if err != nil {
		return nil, errSealedRecordMalformed
	}
	return plaintext, nil
}
