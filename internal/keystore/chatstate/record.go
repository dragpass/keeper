// record.go — the per-conversation record and its sealed file encoding.

package chatstate

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"strconv"
	"strings"
)

// SchemaVersion pins the record layout. An unknown version fails closed rather
// than being read with today's field meanings.
const SchemaVersion = 1

const (
	// OutboxCapacity / ReceivedCapacity bound the record so a long-lived
	// conversation cannot grow the file without limit. Both are rings: the
	// oldest entry is dropped. Falling off the outbox ring means a
	// retransmission that late is answered with ErrNotFound and the position is
	// abandoned, which the contract already allows (ADR S7-4). Falling off the
	// received ring means a redelivery that late would be treated as new, so
	// the ring is the wider of the two.
	OutboxCapacity   = 64
	ReceivedCapacity = 1024

	// MaxCiphertextBytes matches the server's conversation_messages ciphertext
	// column, so the outbox cannot hold something the transport could not have
	// sent anyway.
	MaxCiphertextBytes = 8208
	ivBytes            = 12
)

// Position is one place in one sending chain. Two different plaintexts must
// never occupy the same Position: at that moment AES-GCM is being asked to
// reuse a (key, nonce) pair.
type Position struct {
	Epoch      uint64 `json:"epoch"`
	ChainIndex uint64 `json:"chain_index"`
}

// OutboxEntry is a ciphertext that has already been built, kept so a
// retransmission sends the same bytes instead of encrypting again. Re-encrypting
// advances the chain, which produces a second ciphertext at a second position
// for one plaintext, and the receiver then either fails to open it or diverges.
type OutboxEntry struct {
	ClientMessageID string   `json:"client_message_id"`
	Position        Position `json:"position"`
	IV              []byte   `json:"iv"`
	Ciphertext      []byte   `json:"ciphertext"`
}

// Record is one conversation's whole state. Everything that has to change
// atomically is in here and nothing that has to change atomically is outside,
// which is what lets a single file replacement be the unit of consistency and
// removes any need for an index or a transaction.
type Record struct {
	SchemaVersion  int    `json:"schema_version"`
	OwnerAccountID string `json:"owner_account_id"`
	ConversationID string `json:"conversation_id"`

	// Generation increases on every accepted write. The keyring anchor holds
	// the highest value this device ever committed, so a file that comes back
	// with a lower one announces itself as a restored copy.
	Generation uint64 `json:"generation"`

	// Epoch and NextIndex are the sending chain. NextIndex is the next unused
	// position, so [0, NextIndex) is consumed and never handed out again, even
	// across a crash that lost whatever was going to be encrypted with it.
	Epoch     uint64 `json:"epoch"`
	NextIndex uint64 `json:"next_index"`

	// GroupState is the serialized MLS / ratchet state. Opaque here on purpose:
	// this package owns when it is persisted, not what is in it, and no action
	// in the protocol carries it in either direction.
	GroupState []byte `json:"group_state,omitempty"`

	Outbox   []OutboxEntry `json:"outbox,omitempty"`
	Received []Position    `json:"received,omitempty"`
}

func newRecord(ownerAccountID, conversationID string) *Record {
	return &Record{
		SchemaVersion:  SchemaVersion,
		OwnerAccountID: ownerAccountID,
		ConversationID: conversationID,
	}
}

func (r *Record) findOutbox(clientMessageID string) (OutboxEntry, bool) {
	for _, e := range r.Outbox {
		if e.ClientMessageID == clientMessageID {
			return e, true
		}
	}
	return OutboxEntry{}, false
}

func (r *Record) positionTaken(p Position) bool {
	for _, e := range r.Outbox {
		if e.Position == p {
			return true
		}
	}
	return false
}

func (r *Record) appendOutbox(e OutboxEntry) {
	r.Outbox = append(r.Outbox, e)
	if len(r.Outbox) > OutboxCapacity {
		r.Outbox = append([]OutboxEntry(nil), r.Outbox[len(r.Outbox)-OutboxCapacity:]...)
	}
}

func (r *Record) receivedContains(p Position) bool {
	for _, seen := range r.Received {
		if seen == p {
			return true
		}
	}
	return false
}

func (r *Record) appendReceived(p Position) {
	r.Received = append(r.Received, p)
	if len(r.Received) > ReceivedCapacity {
		r.Received = append([]Position(nil), r.Received[len(r.Received)-ReceivedCapacity:]...)
	}
}

// ────────────────────────────────────────────────────────────────────────
// Sealed file encoding.
//
//	magic(4) || schema(1) || generation(8, big endian) || iv(12) || ciphertext‖tag
//
// The header is cleartext because the AAD has to be rebuilt before the body can
// be opened, and the AAD binds the generation. Tampering with it fails the tag.
// What the cleartext generation gives away to someone already holding the file
// is a rough message count for a conversation they cannot name — the file name
// is an HMAC — which is the price of binding the generation the ADR asks for.
// ────────────────────────────────────────────────────────────────────────

const (
	fileAADDomain = "dragpass.chat.state.file"
	headerBytes   = 4 + 1 + 8 + ivBytes
)

var fileMagic = [4]byte{'D', 'P', 'C', 'S'}

var errSealedRecordMalformed = errors.New("sealed chat state record is malformed")

func fileAAD(ownerAccountID, conversationID string, generation uint64) []byte {
	return []byte(strings.Join([]string{
		fileAADDomain,
		strconv.Itoa(SchemaVersion),
		ownerAccountID,
		conversationID,
		strconv.FormatUint(generation, 10),
	}, "|"))
}

func sealRecord(key []byte, rec *Record, body []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, headerBytes, headerBytes+len(body)+gcm.Overhead())
	copy(out[0:4], fileMagic[:])
	out[4] = byte(SchemaVersion)
	binary.BigEndian.PutUint64(out[5:13], rec.Generation)
	iv := out[13:headerBytes]
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	aad := fileAAD(rec.OwnerAccountID, rec.ConversationID, rec.Generation)
	return gcm.Seal(out, iv, body, aad), nil
}

func openRecord(key []byte, ownerAccountID, conversationID string, sealed []byte) ([]byte, uint64, error) {
	if len(sealed) < headerBytes || [4]byte(sealed[0:4]) != fileMagic {
		return nil, 0, errSealedRecordMalformed
	}
	if int(sealed[4]) != SchemaVersion {
		return nil, 0, errSealedRecordMalformed
	}
	generation := binary.BigEndian.Uint64(sealed[5:13])
	gcm, err := newGCM(key)
	if err != nil {
		return nil, 0, err
	}
	aad := fileAAD(ownerAccountID, conversationID, generation)
	body, err := gcm.Open(nil, sealed[13:headerBytes], sealed[headerBytes:], aad)
	if err != nil {
		return nil, 0, errSealedRecordMalformed
	}
	return body, generation, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
