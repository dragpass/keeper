// send.go — the send transaction, design §7.2.1 T-c.
//
// # The invariant
//
// The record that says "this chain position is being used" reaches the disk
// before the AEAD call that uses it. Encrypting two different plaintexts at
// one (key, nonce) is the single thing in this design that cannot be taken
// back, and everything in this file is arranged around making that order
// impossible to get wrong.
//
// # Why the encryption is inside the lock
//
// The earlier shape reserved a number under the lock, released it, and
// encrypted afterwards. That does not hold once MLS is the chain, because the
// number is not what decides which key is used: the serialized group state is.
// Two processes can take different reserved numbers, both load the same stored
// state, and both encrypt at the same step of the ratchet. So the peek, the
// encryption and both writes are one critical section, and the lock is held
// across an AEAD call. The cost is lock occupancy and it is a known trade.
//
// mls-rs says the same thing from its side: peek_next_key_generation is
// documented as "only safe for synchronous usage of Group APIs". Peeking
// outside the lock is not a variant of this design, it is a different and
// broken one.
//
// # The two writes and the crash window between them
//
//	load ─ burn any unfinished position ─ peek N
//	  write 1: group state + "N is being used"      ← fsynced before the AEAD
//	  encrypt (the ratchet advances past N)
//	  write 2: advanced group state + ciphertext + "nothing pending"
//
// A crash between the two writes leaves write 1 on disk: an intent with no
// ciphertext. Whether N was consumed is unknowable from there, so it is
// treated as consumed and burned. The hole that leaves in the chain is
// ordinary for MLS. Handing N out a second time is not.
//
// # What is deliberately not here
//
// Nothing here logs, and no error message carries the group state, the
// plaintext, or any buffer that passed through the MLS layer — not their bytes,
// not their length, not a digest. The serialized state holds this device's leaf
// signature secret key, so even its size in a log line is a fact about a
// signing key. The one length that does appear in an error is the ciphertext's,
// which the transport carries in the clear anyway.

package chatstate

import (
	"errors"
	"fmt"
)

// maxBurnForward bounds the recovery loop. One burn is all a crash between the
// two writes can ever call for, because write 1 records the state the peek was
// taken from. A larger gap means the file and the library disagree about where
// the ratchet is, and grinding forward through an unbounded number of
// generations to paper over that would be worse than stopping.
const maxBurnForward = 8

// SendCipher is the MLS half of one send. Every method is called from inside
// the conversation lock and in one order; the interface exists so the ordering
// can be tested without the MLS library linked, and so this package keeps
// owning when bytes reach the disk.
type SendCipher interface {
	// Load restores the session from the record's stored state. It is called
	// inside the lock on every send: a session carried across a lock release
	// is a copy of the state with nothing protecting it.
	Load(groupState []byte) error

	// Peek reports the position the next Seal would take, without taking it.
	Peek() (Position, error)

	// Burn consumes one position without encrypting anything.
	Burn() error

	// Seal encrypts and advances the ratchet past the peeked position.
	Seal(plaintext, authenticatedData []byte) ([]byte, error)

	// State serializes the session as it now stands. Nothing the MLS library
	// did is durable until what this returns is written.
	State() ([]byte, error)
}

// SendRequest is one outbound message.
type SendRequest struct {
	ClientMessageID string
	Plaintext       []byte

	// ExpectedEpoch refuses a send built against a different epoch than the
	// one the record is on. Zero means the caller is not asserting one.
	ExpectedEpoch uint64
}

// SendResult carries what the transport needs and nothing else. The plaintext
// does not come back and neither does the group state.
type SendResult struct {
	Entry OutboxEntry

	// Created is false when a stored ciphertext answered instead. A
	// retransmission sends the same bytes; encrypting again would take a
	// second position for one message and the receiver would see two.
	Created bool

	// Generation is the record's write counter, for the rollback anchor.
	Generation uint64

	// Burned lists positions this call abandoned before sending. Non-empty
	// means an earlier send died between its two writes.
	Burned []Position
}

var (
	// ErrNoGroupState — this conversation has no MLS group yet. Distinct from
	// a storage failure: the answer is to establish a group, not to retry.
	ErrNoGroupState = errors.New("chat state has no group state for this conversation")

	// ErrEpochStale — the caller built this send against an epoch the record
	// has moved past.
	ErrEpochStale = errors.New("chat state is no longer on the epoch this send was built for")

	// ErrBurnForward — an unfinished position could not be abandoned within
	// the bound. Sending anyway would risk the one failure this package
	// exists to prevent, so it does not.
	ErrBurnForward = errors.New("chat state could not abandon an unfinished chain position")
)

// Send encrypts one message and returns the bytes to transmit. The transmission
// happens after this returns, outside the lock.
func (s *Store) Send(
	conversationID string, wm ServerWatermark, req SendRequest, cipher SendCipher,
) (SendResult, error) {
	if req.ClientMessageID == "" {
		return SendResult{}, errors.New("send needs a client message id")
	}
	if len(req.Plaintext) == 0 {
		return SendResult{}, errors.New("send needs a plaintext")
	}
	var out SendResult
	err := s.withConversation(conversationID, func(p convPaths) error {
		rec, anchor, err := s.loadChecked(p, conversationID, wm)
		if err != nil {
			return err
		}
		if existing, ok := rec.findOutbox(req.ClientMessageID); ok {
			out = SendResult{Entry: existing, Generation: rec.Generation}
			return nil
		}
		if len(rec.GroupState) == 0 {
			return ErrNoGroupState
		}
		if err := cipher.Load(rec.GroupState); err != nil {
			return err
		}
		burned, err := burnUnfinished(rec, cipher)
		if err != nil {
			return err
		}

		position, err := cipher.Peek()
		if err != nil {
			return err
		}
		if req.ExpectedEpoch != 0 && req.ExpectedEpoch != position.Epoch {
			return ErrEpochStale
		}
		if rec.positionTaken(position) {
			return ErrPositionTaken
		}

		// Write 1. The state is re-serialized even when nothing was burned,
		// because the peek has to describe the state that is on the disk: if
		// the record held an older state than the live session, a restart
		// would burn the wrong number.
		state, err := cipher.State()
		if err != nil {
			return err
		}
		loaded := rec.Generation
		rec.GroupState = state
		// Forward only. commit() copies this into the anchor, and the anchor's
		// epoch is one of the two axes a rewound record is caught on, so a
		// group state that came back behind the record must not be allowed to
		// lower the ceiling it will later be judged against.
		if position.Epoch > rec.Epoch {
			rec.Epoch = position.Epoch
		}
		rec.PendingSend = &position
		if err := s.commit(p, rec, loaded, anchor); err != nil {
			return err
		}

		ciphertext, err := cipher.Seal(req.Plaintext, position.declaration())
		if err != nil {
			return err
		}
		if len(ciphertext) == 0 || len(ciphertext) > MaxCiphertextBytes {
			return fmt.Errorf("mls ciphertext is %d bytes, outside 1..%d",
				len(ciphertext), MaxCiphertextBytes)
		}

		// Write 2. The advanced state, the ciphertext and the cleared intent
		// land together, so a crash before this leaves an intent to burn and a
		// crash after it leaves nothing to do.
		advanced, err := cipher.State()
		if err != nil {
			return err
		}
		entry := OutboxEntry{
			ClientMessageID: req.ClientMessageID,
			Position:        position,
			Ciphertext:      ciphertext,
		}
		loaded = rec.Generation
		rec.GroupState = advanced
		rec.PendingSend = nil
		rec.appendOutbox(entry)
		if err := s.commit(p, rec, loaded, anchor); err != nil {
			return err
		}
		out = SendResult{Entry: entry, Created: true, Generation: rec.Generation, Burned: burned}
		return nil
	})
	return out, err
}

// burnUnfinished abandons a position whose fate the record cannot settle.
//
// The rule is one-directional on purpose. Burning a position that was never
// used costs a hole in the chain, which MLS handles. Not burning one that was
// used costs a (key, nonce) reuse, which nothing handles. So an unfinished
// intent is always treated as used.
//
// It burns only while the ratchet has not already passed the pending position.
// An intent left over from an epoch the group has since left has nothing to
// burn: that secret tree is gone.
//
// The burn is in memory here. What makes it durable is the caller writing the
// state afterwards, which write 1 of the send does.
func burnUnfinished(rec *Record, cipher SendCipher) ([]Position, error) {
	if rec.PendingSend == nil {
		return nil, nil
	}
	pending := *rec.PendingSend
	var burned []Position
	for range maxBurnForward {
		position, err := cipher.Peek()
		if err != nil {
			return nil, err
		}
		if position.Epoch != pending.Epoch || position.Generation > pending.Generation {
			rec.PendingSend = nil
			return burned, nil
		}
		if err := cipher.Burn(); err != nil {
			return nil, err
		}
		burned = append(burned, position)
	}
	return nil, ErrBurnForward
}
