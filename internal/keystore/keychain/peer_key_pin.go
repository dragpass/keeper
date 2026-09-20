package keychain

// peer_key_pin.go — peer account key pins (account key trust v1).
//
// The server hands out every member public key the Extension wraps a Group DEK
// to, and until now nothing recorded which key it handed out last time. A pin
// is that record: one entry per (owner account, peer account) holding the
// fingerprint the owner has already accepted plus how much trust it carries.
// The wrap actions consult it, so a server that swaps a member's key has to get
// past a comparison the server cannot write to.
//
// Two shapes live in the keyring, both under config.Service like every other
// slot:
//
//	peer-pin:<owner>:<peer>       → PeerKeyPin JSON (~230 bytes)
//	peer-pin-index:<owner>:<n>    → {"v":1,"peers":[...]} , 48 ids per chunk
//
// The index exists because SecretStore has Get / Set / Delete and no listing.
// It is chunked rather than kept as one blob because the Windows Credential
// Manager caps an entry at roughly 2.5 KB, and pins are per peer — an org with
// thirty members would outgrow a single entry. Chunk numbers are assigned once
// and never reused or renumbered: enumeration walks n = 0 upward and stops at
// the first ErrSecretNotFound, so a renumber would silently truncate the set.
// A delete empties its slot in place and leaves the chunk behind.
//
// Everything here goes through the SecretStore interface, so the MemorySecretStore
// unit tests exercise the same path the platform keyring takes.

import (
	"encoding/json"
	"errors"
	"strconv"

	"github.com/dragpass/keeper/config"
)

// PeerKeyPinVersion is the schema version written into every pin record and
// index chunk. A reader that meets a higher number is looking at a format it
// does not know.
const PeerKeyPinVersion = 1

// PeerKeyPinIndexChunkSize caps how many peer ids one index chunk carries.
// 48 ids of 36 characters plus their quotes and commas comes to about 1.9 KB
// with the JSON overhead, which stays under the smallest per-entry limit any
// supported platform imposes. The number is part of the on-disk contract:
// changing it re-partitions indexes that already exist.
const PeerKeyPinIndexChunkSize = 48

// PeerKeyPinMaxItemBytes is the ceiling both record shapes are held to before
// they are written. A value over it is a bug in the caller, not something to
// hand to the keyring and hope.
const PeerKeyPinMaxItemBytes = 2048

// PeerKeyPinState is how much the owner trusts the pinned fingerprint.
//
//   - tofu:     first observation, accepted without anyone checking it.
//   - verified: a human compared the fingerprint out of band.
//   - rotated:  a signed rotation chain moved the pin forward. A pin that was
//     verified does not stay verified across a rotation.
//   - changed:  the observed key does not match and no valid chain explains
//     it. Never stored — it is a verdict the wrap path returns, and the pin it
//     was measured against is left exactly as it was.
type PeerKeyPinState string

const (
	PeerKeyPinStateTOFU     PeerKeyPinState = "tofu"
	PeerKeyPinStateVerified PeerKeyPinState = "verified"
	PeerKeyPinStateRotated  PeerKeyPinState = "rotated"
	PeerKeyPinStateChanged  PeerKeyPinState = "changed"
)

// PeerKeyPin is the stored record. Times are Unix seconds. VerifiedAt and
// LastRotationFingerprint are omitted when unset, which is also how they are
// cleared: a rotation drops VerifiedAt, an out-of-band confirmation drops
// LastRotationFingerprint.
type PeerKeyPin struct {
	V                       int             `json:"v"`
	Fingerprint             string          `json:"fingerprint"`
	State                   PeerKeyPinState `json:"state"`
	FirstSeenAt             int64           `json:"first_seen_at"`
	LastSeenAt              int64           `json:"last_seen_at"`
	VerifiedAt              int64           `json:"verified_at,omitempty"`
	LastRotationFingerprint string          `json:"last_rotation_fingerprint,omitempty"`
}

// PeerKeyPinEntry pairs a peer account id with its record, which is what a
// listing needs and the stored JSON does not carry (the id is in the key).
type PeerKeyPinEntry struct {
	AccountID string
	Pin       PeerKeyPin
}

type peerKeyPinIndexChunk struct {
	V     int      `json:"v"`
	Peers []string `json:"peers"`
}

// PeerKeyPinAccount builds the keyring account name for one pin. Exported so
// tests can assert the layout rather than infer it.
func PeerKeyPinAccount(ownerAccountID, peerAccountID string) string {
	return config.PeerKeyPinPrefix + ownerAccountID + ":" + peerAccountID
}

// PeerKeyPinIndexAccount builds the keyring account name for one index chunk.
func PeerKeyPinIndexAccount(ownerAccountID string, chunk int) string {
	return config.PeerKeyPinIndexPrefix + ownerAccountID + ":" + strconv.Itoa(chunk)
}

// GetPeerKeyPin reads one pin. A missing pin surfaces as ErrSecretNotFound,
// which callers read as "first observation" rather than as a failure.
func GetPeerKeyPin(store SecretStore, ownerAccountID, peerAccountID string) (PeerKeyPin, error) {
	raw, err := store.Get(config.Service, PeerKeyPinAccount(ownerAccountID, peerAccountID))
	if err != nil {
		return PeerKeyPin{}, err
	}
	var pin PeerKeyPin
	if err := json.Unmarshal([]byte(raw), &pin); err != nil {
		return PeerKeyPin{}, errors.New("peer key pin record is not readable JSON")
	}
	return pin, nil
}

// SavePeerKeyPin writes the record and makes sure the index can find it again.
// The index add is idempotent, so re-saving an existing pin does not grow it.
func SavePeerKeyPin(store SecretStore, ownerAccountID, peerAccountID string, pin PeerKeyPin) error {
	pin.V = PeerKeyPinVersion
	encoded, err := json.Marshal(pin)
	if err != nil {
		return err
	}
	if len(encoded) > PeerKeyPinMaxItemBytes {
		return errors.New("peer key pin record exceeds the keyring entry size limit")
	}
	if err := store.Set(config.Service, PeerKeyPinAccount(ownerAccountID, peerAccountID), string(encoded)); err != nil {
		return err
	}
	return addPeerKeyPinIndexEntry(store, ownerAccountID, peerAccountID)
}

// DeletePeerKeyPin removes one pin and its index entry. Idempotent: the
// returned bool reports whether a record was actually there, and a missing one
// is a successful no-op.
//
// The bool is reported even alongside an error. The two writes are not atomic,
// so a delete can remove the record and then fail to update the index; saying
// "nothing was forgotten" there would be wrong in the direction that matters,
// since the pin really is gone. The caller gets both facts and the stale index
// entry is dropped by the next listing.
func DeletePeerKeyPin(store SecretStore, ownerAccountID, peerAccountID string) (bool, error) {
	existed := true
	if err := store.Delete(config.Service, PeerKeyPinAccount(ownerAccountID, peerAccountID)); err != nil {
		if !errors.Is(err, ErrSecretNotFound) {
			return false, err
		}
		existed = false
	}
	if _, err := removePeerKeyPinIndexEntry(store, ownerAccountID, peerAccountID); err != nil {
		return existed, err
	}
	return existed, nil
}

// ListPeerKeyPins reads every pin the owner's index points at, in index order.
// An id whose record is gone is dropped from the index instead of being
// reported, so a delete that died between the two writes repairs itself here.
func ListPeerKeyPins(store SecretStore, ownerAccountID string) ([]PeerKeyPinEntry, error) {
	chunks, err := readPeerKeyPinIndex(store, ownerAccountID)
	if err != nil {
		return nil, err
	}

	entries := make([]PeerKeyPinEntry, 0, len(chunks)*PeerKeyPinIndexChunkSize)
	for n, chunk := range chunks {
		kept := make([]string, 0, len(chunk.Peers))
		for _, peerAccountID := range chunk.Peers {
			pin, err := GetPeerKeyPin(store, ownerAccountID, peerAccountID)
			if err != nil {
				if errors.Is(err, ErrSecretNotFound) {
					continue // stale index entry — dropped by the rewrite below
				}
				return nil, err
			}
			kept = append(kept, peerAccountID)
			entries = append(entries, PeerKeyPinEntry{AccountID: peerAccountID, Pin: pin})
		}
		if len(kept) == len(chunk.Peers) {
			continue
		}
		chunk.Peers = kept
		if err := writePeerKeyPinIndexChunk(store, ownerAccountID, n, chunk); err != nil {
			return nil, err
		}
	}
	return entries, nil
}

// readPeerKeyPinIndex walks chunk 0 upward and stops at the first missing
// number. That is the whole reason chunks are never renumbered.
func readPeerKeyPinIndex(store SecretStore, ownerAccountID string) ([]peerKeyPinIndexChunk, error) {
	var chunks []peerKeyPinIndexChunk
	for n := 0; ; n++ {
		raw, err := store.Get(config.Service, PeerKeyPinIndexAccount(ownerAccountID, n))
		if err != nil {
			if errors.Is(err, ErrSecretNotFound) {
				return chunks, nil
			}
			return nil, err
		}
		var chunk peerKeyPinIndexChunk
		if err := json.Unmarshal([]byte(raw), &chunk); err != nil {
			return nil, errors.New("peer key pin index chunk is not readable JSON")
		}
		chunks = append(chunks, chunk)
	}
}

func writePeerKeyPinIndexChunk(store SecretStore, ownerAccountID string, n int, chunk peerKeyPinIndexChunk) error {
	chunk.V = PeerKeyPinVersion
	if chunk.Peers == nil {
		chunk.Peers = []string{}
	}
	if len(chunk.Peers) > PeerKeyPinIndexChunkSize {
		return errors.New("peer key pin index chunk holds too many ids")
	}
	encoded, err := json.Marshal(chunk)
	if err != nil {
		return err
	}
	if len(encoded) > PeerKeyPinMaxItemBytes {
		return errors.New("peer key pin index chunk exceeds the keyring entry size limit")
	}
	return store.Set(config.Service, PeerKeyPinIndexAccount(ownerAccountID, n), string(encoded))
}

// addPeerKeyPinIndexEntry appends to the last chunk while it has room and
// starts a new one otherwise. An id already in any chunk is left alone.
func addPeerKeyPinIndexEntry(store SecretStore, ownerAccountID, peerAccountID string) error {
	chunks, err := readPeerKeyPinIndex(store, ownerAccountID)
	if err != nil {
		return err
	}
	for _, chunk := range chunks {
		for _, id := range chunk.Peers {
			if id == peerAccountID {
				return nil
			}
		}
	}
	if len(chunks) > 0 {
		last := len(chunks) - 1
		if len(chunks[last].Peers) < PeerKeyPinIndexChunkSize {
			chunks[last].Peers = append(chunks[last].Peers, peerAccountID)
			return writePeerKeyPinIndexChunk(store, ownerAccountID, last, chunks[last])
		}
	}
	return writePeerKeyPinIndexChunk(
		store, ownerAccountID, len(chunks), peerKeyPinIndexChunk{Peers: []string{peerAccountID}},
	)
}

// removePeerKeyPinIndexEntry takes the id out of whichever chunk holds it. The
// chunk itself stays, empty if that was its last id.
func removePeerKeyPinIndexEntry(store SecretStore, ownerAccountID, peerAccountID string) (bool, error) {
	chunks, err := readPeerKeyPinIndex(store, ownerAccountID)
	if err != nil {
		return false, err
	}
	for n, chunk := range chunks {
		kept := make([]string, 0, len(chunk.Peers))
		found := false
		for _, id := range chunk.Peers {
			if id == peerAccountID {
				found = true
				continue
			}
			kept = append(kept, id)
		}
		if !found {
			continue
		}
		chunk.Peers = kept
		if err := writePeerKeyPinIndexChunk(store, ownerAccountID, n, chunk); err != nil {
			return false, err
		}
		return true, nil
	}
	return false, nil
}
