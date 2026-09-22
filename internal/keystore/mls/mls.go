// Package mls links the MLS (RFC 9420) implementation Keeper uses and keeps
// the serialized group state it produces inside the existing chat state record.
//
// # What is here and what is not
//
// This is the skeleton: the library is linked, its policy is fixed, and the
// bytes it serializes reach disk through chatstate's whole-file replacement.
// The send and receive ordering that has to sit on top of it — naming the
// generation before consuming it, burning an uncertain one after a crash,
// holding the lock across the encryption — is not here yet.
//
// # Build tag
//
// The binding needs cgo and a Rust static library, so it sits behind the `mls`
// build tag and a stub answers ErrUnavailable without it. The default build is
// byte-for-byte what it was: the Linux release still builds with CGO_ENABLED=0
// and still ships a static binary, which linking this would end. Keeping the
// tag off by default is what lets the library be measured and reviewed before
// that trade is made rather than as a side effect of making it.
//
// # What the state blob holds
//
// More than ratchet state. mls-rs's snapshot carries the epoch secrets, the
// secret tree, the key schedule, the private tree and, in the same structure,
// this device's leaf signature secret key. So the record's seal key is
// protecting a signing key and not only decryption material, and losing the
// file to an attacker who also has the seal key means losing the ability to
// prove this device authored anything.
//
// # Memory
//
// mls-rs protects key material with zeroize, which overwrites a buffer when the
// value holding it is dropped. Measured coverage (mls-rs 0.56.0 /
// mls-rs-core 0.27.0): the serialized state and prior-epoch blobs, the key
// schedule's five secrets, the secret tree's node secrets, every derived
// message key and nonce, the signature and HPKE secret keys, and application
// plaintext.
//
// That is the whole of the protection, and it is narrower than the list makes
// it sound: it covers one buffer at the moment its owner is dropped. It does
// not reach copies made along the way, the allocation a growing Vec abandons,
// pages the OS wrote to swap, or the image in a core dump. Neither mls-rs nor
// any of its 112 dependencies calls mlock, VirtualLock, madvise or mprotect —
// zeroize's own documentation puts those explicitly out of scope — so the Rust
// side allocates from a plain global heap and Keeper's memguard arena does not
// extend over any of it. Secrets in this package's Go buffers are not covered
// either unless the caller wipes them.
package mls

import (
	"errors"

	"github.com/dragpass/keeper/internal/keystore/chatstate"
)

// ErrUnavailable — this binary was built without the MLS library. Distinct from
// every other failure so a caller never reads "no group" when the real answer is
// "no library".
var ErrUnavailable = errors.New("mls: this build does not include the MLS library")

// WireForm is the framing a message actually went out in, read back off the
// encoded bytes. Asserting on this rather than on the setting that produced it
// is what would catch an upstream default changing under us.
type WireForm uint8

const (
	WireFormOther WireForm = iota
	WireFormPublicMessage
	WireFormPrivateMessage
	WireFormWelcome
	WireFormKeyPackage
	WireFormGroupInfo
)

func (w WireForm) String() string {
	switch w {
	case WireFormPublicMessage:
		return "PublicMessage"
	case WireFormPrivateMessage:
		return "PrivateMessage"
	case WireFormWelcome:
		return "Welcome"
	case WireFormKeyPackage:
		return "KeyPackage"
	case WireFormGroupInfo:
		return "GroupInfo"
	default:
		return "other"
	}
}

// Processed is the outcome of applying one inbound message. Plaintext is set
// only for an application message and is the caller's to wipe.
type Processed struct {
	Epoch       uint64
	Removed     bool
	Application bool
	Plaintext   []byte

	// SenderLeafIndex is SenderData.leaf_index, which the wire format keeps
	// encrypted. It is half of the four-slot name of an inbound position and
	// there is no way to learn it except by decrypting.
	SenderLeafIndex uint32

	// AuthenticatedData is the sender's cleartext declaration.
	AuthenticatedData []byte

	// KeyGeneration is the generation the library derived its keys from, or
	// nil when it could not tell. Nil is an answer and never a zero: upstream
	// reaches its None by folding an extraction error into a default, so a
	// substituted zero would be indistinguishable from a checked match.
	KeyGeneration *uint32
}

// Persist flushes the session's group state into the conversation's record.
//
// The flush and the write are two steps because only the second is durable.
// mls-rs advances its secret tree in memory and writes nothing until it is
// asked, so anything that moved the group forward is lost unless this runs
// after it. Pairing an advance with this call is an invariant of the layer
// above; nothing below checks it.
func Persist(
	store *chatstate.Store,
	conversationID string,
	wm chatstate.ServerWatermark,
	s *Session,
) (uint64, error) {
	blob, err := s.Flush()
	if err != nil {
		return 0, err
	}
	return store.SaveGroupState(conversationID, wm, blob)
}

// Restore loads the conversation's stored group state into the session. It
// reports false when the conversation has no group state yet, which is an
// ordinary state and not an error.
func Restore(
	store *chatstate.Store,
	conversationID string,
	wm chatstate.ServerWatermark,
	s *Session,
) (bool, error) {
	blob, err := store.LoadGroupState(conversationID, wm)
	if err != nil {
		return false, err
	}
	if len(blob) == 0 {
		return false, nil
	}
	return true, s.Load(blob)
}

// ────────────────────────────────────────────────────────────────────────
// The seam chatstate drives its transactions through.
// ────────────────────────────────────────────────────────────────────────

// Cipher adapts a Session to chatstate's SendCipher and ReceiveCipher. It adds
// no state of its own: every method is one Session call, and the ordering,
// the lock and the durability all belong to chatstate.
//
// Load is called on every transaction even when the session already holds the
// group, because the record is the authority on where the ratchet is and
// another process may have moved it since this session last looked.
type Cipher struct{ session *Session }

func NewCipher(s *Session) *Cipher { return &Cipher{session: s} }

func (c *Cipher) Load(groupState []byte) error { return c.session.Load(groupState) }

func (c *Cipher) Peek() (chatstate.Position, error) {
	epoch, leaf, generation, err := c.session.SendPosition()
	if err != nil {
		return chatstate.Position{}, err
	}
	return chatstate.Position{
		Epoch:           epoch,
		SenderLeafIndex: leaf,
		// Fixed rather than asked: encrypt_control_messages is pinned false,
		// so a Commit goes out as a PublicMessage and consumes nothing. The
		// handshake ratchet never advances, which is what leaves the send
		// discipline with this one axis to defend. Flipping that setting
		// brings the other axis back, and mls-rs exposes neither a peek nor a
		// burn for it.
		ContentType: chatstate.ContentTypeApplication,
		Generation:  uint64(generation),
	}, nil
}

func (c *Cipher) Burn() error { return c.session.BurnGeneration() }

func (c *Cipher) Seal(plaintext, authenticatedData []byte) ([]byte, error) {
	return c.session.Encrypt(plaintext, authenticatedData)
}

func (c *Cipher) State() ([]byte, error) { return c.session.Flush() }

func (c *Cipher) Open(message []byte) (chatstate.Opened, error) {
	processed, err := c.session.Process(message)
	if err != nil {
		return chatstate.Opened{}, err
	}
	return chatstate.Opened{
		Epoch:             processed.Epoch,
		SenderLeafIndex:   processed.SenderLeafIndex,
		Application:       processed.Application,
		Removed:           processed.Removed,
		AuthenticatedData: processed.AuthenticatedData,
		KeyGeneration:     processed.KeyGeneration,
		Plaintext:         processed.Plaintext,
	}, nil
}
