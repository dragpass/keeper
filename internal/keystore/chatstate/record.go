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
// than being read with today's field meanings, which is exactly what a
// version-1 record needs here: its received marks named only (epoch,
// chain_index), so decoding one under this layout would leave every mark on
// leaf 0 at generation 0 — a deduplication set that silently discards live
// messages rather than one that is merely incomplete.
const SchemaVersion = 2

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

// ContentType says which of a sender's two ratchets a position sits on. A
// string rather than a small integer so that the zero value is not also a valid
// answer: a position that never named its ratchet must not read as a handshake
// position.
type ContentType string

const (
	ContentTypeHandshake   ContentType = "handshake"
	ContentTypeApplication ContentType = "application"
)

func (c ContentType) valid() bool {
	return c == ContentTypeHandshake || c == ContentTypeApplication
}

// Position is one place in one ratchet. Two different plaintexts must never
// occupy the same Position: at that moment AES-GCM is being asked to reuse a
// (key, nonce) pair.
//
// Naming that place takes four slots, not two. MLS gives every sender its own
// sender ratchet (RFC 9420 §9.1) and gives each sender two of them, handshake
// and application (§6.3.1), so (epoch, generation) names a different message
// for every member and every axis. Judging deliveries on those two alone
// discards one member's generation 0 as a redelivery of another member's, which
// loses an ordinary message rather than a repeated one.
//
// The MLS send path fills all four, because SendCipher.Peek reads this
// device's own leaf and axis off the group state. The pre-MLS commit_outbox
// path fills only Epoch and Generation and leaves the other two at zero, which
// is what localLeafIndex reads a named axis as: proof that the position came
// from a peek and its leaf is real, rather than a default.
type Position struct {
	Epoch           uint64      `json:"epoch"`
	SenderLeafIndex uint32      `json:"sender_leaf_index"`
	ContentType     ContentType `json:"content_type"`

	// Generation is the step along that one sender's one ratchet. It is not
	// Record.Generation, which counts this file's writes.
	Generation uint64 `json:"generation"`
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

// PendingCommit is a Commit this device built and posted, whose fate the
// server has not yet told us. At most one exists per conversation.
//
// There is no next_group_state field, and its absence is the persistence form
// this design picked (design §7.3.1 offered two). The next epoch's state lives
// inside GroupState, because mls-rs holds a built Commit in Group.pending_commit
// and Snapshot carries that field through write_to_storage and back through
// load_group. Keeping the shape the library already has buys three things our
// own copy would not: the library refuses a second build while one is pending
// (MlsError::ExistingPendingCommit), processing somebody else's Commit drops
// ours in the same operation that applies theirs, and a restart finds it
// without a second serialization format to version. What it costs is that the
// confirmed state and the fork share one blob, so keeping the rollback anchor
// on the confirmed axis is this package's job rather than the file layout's —
// see commit.go and Record.Epoch.
type PendingCommit struct {
	// ClientCommitID is the server's idempotency key. It is the single
	// authority on "was my Commit the one that won", which is why a device
	// that lost the response asks with it rather than guessing.
	ClientCommitID string `json:"client_commit_id"`

	// ExpectedEpoch is the confirmed epoch this Commit was built against and
	// the value the server compares under its CAS.
	ExpectedEpoch uint64 `json:"expected_epoch"`

	// Commit is the message to post, kept so a retry after a lost response
	// sends the same bytes rather than building a second Commit.
	Commit []byte `json:"commit"`

	// Welcome is released only once the Commit is accepted (RFC 9420 §14).
	Welcome []byte `json:"welcome,omitempty"`
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

	// PendingSend names the position a send declared it was about to use
	// before it called the AEAD. Its presence after a restart means that call
	// may or may not have happened, and an unfinished position is treated as
	// used (send.go).
	PendingSend *Position `json:"pending_send,omitempty"`

	// Pending is the one Commit this device has built and not yet settled.
	// Separate from Epoch and GroupState above because those two are the
	// confirmed state and a built Commit is not confirmed; see commit.go.
	Pending *PendingCommit `json:"pending,omitempty"`

	// RemovalLatch is the accounts this device may not encrypt new messages
	// past (design §6.4.1 S-1), sorted. See latch.go for how it moves.
	//
	// Absent in a record written before it existed, which reads as nothing
	// latched and is true. SchemaVersion is not raised for it: a Keeper old
	// enough to drop the field on rewrite verifies only the v2 permit
	// canonical, so once the server signs v3 it cannot open this store at all.
	RemovalLatch []string `json:"removal_latch,omitempty"`

	// LeafReplacementLatch is the (account, new leaf key) pairs this device
	// may not encrypt new messages past until its confirmed group holds no
	// other key of that account (design M4.4), sorted. See latch.go.
	//
	// SchemaVersion is not raised for it, on the same argument as
	// RemovalLatch, one version later: the field reaches a record only from a
	// v4 permit, a Keeper old enough to drop it on rewrite refuses every v4
	// permit (it neither decodes the new slot nor verifies the new
	// canonical), and this Keeper refuses every v3 one. So no binary that
	// would lose the field ever rewrites a record once the field can be set.
	// Raising the version would buy nothing and would make every existing
	// record unreadable, because an unknown version fails closed.
	LeafReplacementLatch []LeafReplacement `json:"leaf_replacement_latch,omitempty"`

	Outbox   []OutboxEntry `json:"outbox,omitempty"`
	Received []Position    `json:"received,omitempty"`

	// History is the sealed local copy of delivered messages. It is in this
	// struct rather than in a file of its own so that confirming a delivery
	// and storing its copy is one replacement; see history.go for what that
	// settles and what it leaves open.
	History []HistoryEntry `json:"history,omitempty"`
}

func newRecord(ownerAccountID, conversationID string) *Record {
	return &Record{
		SchemaVersion:  SchemaVersion,
		OwnerAccountID: ownerAccountID,
		ConversationID: conversationID,
	}
}

// enterEpoch moves the record onto a new epoch and restarts the sending chain
// counter with it. Forward only, and a no-op when the epoch is not new: the
// anchor's epoch is copied from this field, so a value that went backwards
// would lower the ceiling the next load is judged against.
//
// NextIndex and the anchor's ReservedBefore both count positions along *one*
// epoch's ratchet, and MLS restarts generation at 0 in every new epoch. Before
// MLS there was only ever one epoch, so the question could not arise. Now it
// decides whether either rollback axis still works after the first Commit.
//
// A NextIndex carried across the boundary makes the watermark comparison
// `nextIndex > rec.NextIndex` false for the whole of the new epoch, so axis 2
// stops detecting rather than falsely latching — the worse of the two
// directions, because nothing reports it. A ReservedBefore carried across is
// the mirror for axis 1: a restored file could claim every position below the
// old epoch's ceiling without tripping it.
//
// Resetting them opens nothing. A rewind across the boundary is caught on its
// own by `rec.Epoch < a.Epoch`, and anchor.Epoch only ever moves forward
// because commit() copies it from this field and this method is the only way
// to raise it. Nothing that goes backwards can reach the reset.
//
// The anchor's half is in commit() rather than beside this one: the ceiling
// and the epoch it belongs to have to land in the same keyring write.
func (r *Record) enterEpoch(epoch uint64) {
	if epoch <= r.Epoch {
		return
	}
	r.Epoch = epoch
	r.NextIndex = 0
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

// sealedBySendPath reports whether the MLS send path already built a
// ciphertext at this epoch and generation.
//
// The two send paths share one counter but never one Position: Send names the
// leaf and the axis, the pre-MLS commit_outbox path leaves both empty, so
// positionTaken — which compares whole Positions — cannot see the collision.
// Neither can NextIndex any more: Send raising it is exactly what makes a
// generation Send already spent look handed-out to commit_outbox. Only the
// numbers can meet, and one number carrying two ciphertexts is what this
// package exists to refuse.
func (r *Record) sealedBySendPath(p Position) bool {
	for _, e := range r.Outbox {
		if e.Position.ContentType.valid() &&
			e.Position.Epoch == p.Epoch && e.Position.Generation == p.Generation {
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

// localLeafIndex reports this device's own leaf in the group, and whether the
// record has ever learned it.
//
// The authoritative copy is inside GroupState, which this package treats as
// opaque and which the protocol edge cannot read without linking the MLS
// library into it. What is readable here is the positions this device's own
// send path wrote: those come from SendCipher.Peek, so they carry the real
// leaf and name the ratchet they sit on. The positions the pre-MLS
// commit_outbox path writes name neither, and that is what separates "never
// learned" from "leaf 0" — a distinction a bare uint32 cannot carry, and the
// one a watermark's leaf slot has to be judged against.
func (r *Record) localLeafIndex() (uint32, bool) {
	if r.PendingSend != nil && r.PendingSend.ContentType.valid() {
		return r.PendingSend.SenderLeafIndex, true
	}
	for i := len(r.Outbox) - 1; i >= 0; i-- {
		if r.Outbox[i].Position.ContentType.valid() {
			return r.Outbox[i].Position.SenderLeafIndex, true
		}
	}
	return 0, false
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
