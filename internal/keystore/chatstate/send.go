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
	"time"
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

	// SenderOf names the credential of the leaf at this index in the confirmed
	// group. Send asks it for its own leaf, so the sealed copy of a sent
	// message names this device the way a delivered one names its sender: from
	// the group's tree, never from the caller.
	SenderOf(leafIndex uint32) (Sender, error)

	RosterReader
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
		// After the retransmission branch on purpose. Resending stored bytes
		// touches neither the ratchet nor the epoch, so an unsettled Commit
		// has nothing to say about it. A new message is different: which epoch
		// it belongs to is undecided while a Commit of ours is in flight, and
		// encrypting under a guess is what §7.3.2's third outcome refuses.
		if rec.Pending != nil {
			return ErrCommitPending
		}
		if len(rec.GroupState) == 0 {
			return ErrNoGroupState
		}
		if err := cipher.Load(rec.GroupState); err != nil {
			return err
		}
		// Ahead of burnUnfinished and the peek, not only ahead of the seal: a
		// refused send must leave the ratchet exactly where it found it.
		latch, err := judgeLatches(rec, wm, cipher)
		if err != nil {
			return err
		}
		if latch.held() {
			return s.refuseWhileLatched(p, rec, anchor, latch)
		}
		latch.apply(rec)
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
		// Before write 1, so a leaf this cannot name refuses the send with
		// nothing consumed rather than after the AEAD.
		self, err := cipher.SenderOf(position.SenderLeafIndex)
		if err != nil {
			return err
		}
		if self.AccountID == "" || self.DeviceID == "" {
			return errors.New("send could not name this device's own leaf")
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
		rec.enterEpoch(position.Epoch)

		// The chain counters have to record the position this send is taking,
		// the same way Reserve records the ones it hands out. Not bookkeeping:
		// axis 2 compares the server's count against NextIndex, and a server
		// only ever has a count once a send declared a position — which only
		// this path does. A send that left NextIndex at 0 would therefore
		// latch the conversation on the first watermark that ever existed for
		// it, every time, rather than eventually.
		//
		// The number comes from the peek, which is already past whatever
		// burnUnfinished consumed, so abandoned positions land in the counters
		// too instead of being handed out again after a crash.
		//
		// The ceiling reaches the keyring before the file advances into it,
		// the order Reserve takes and for the same reason: the only crash
		// window it leaves has the file ahead of the anchor, the harmless
		// direction. It is only ever raised here, never lowered, so a crash in
		// that window cannot leave a ceiling below a NextIndex the file on
		// disk still carries. commit() does the per-epoch reset, once the file
		// is down and in the same write that moves the anchor's epoch.
		need := position.Generation + 1
		anchor.ReservedBefore = max(anchor.ReservedBefore, need)
		if err := saveAnchor(s.secrets, p.tag, anchor); err != nil {
			return err
		}
		rec.NextIndex = max(rec.NextIndex, need)
		rec.PendingSend = &position
		if err := s.commit(p, rec, loaded, anchor); err != nil {
			return err
		}

		ciphertext, err := cipher.Seal(req.Plaintext, position.declaration())
		if err != nil {
			return err
		}
		crashAt(CrashSendAfterSeal)
		if len(ciphertext) == 0 || len(ciphertext) > MaxCiphertextBytes {
			return fmt.Errorf("mls ciphertext is %d bytes, outside 1..%d",
				len(ciphertext), MaxCiphertextBytes)
		}

		// Write 2. The advanced state, the ciphertext, the cleared intent and
		// the sealed copy of the plaintext land together, so a crash before
		// this leaves an intent to burn and a crash after it leaves nothing to
		// do. The copy is in the same write as the outbox entry because it is
		// the only one this device will ever have: the library will not open
		// its own message (history.go).
		advanced, err := cipher.State()
		if err != nil {
			return err
		}
		now := time.Now()
		sent, err := s.sealSentHistory(conversationID, req.ClientMessageID, position, self, req.Plaintext, now)
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
		rec.appendHistory(sent, s.HistoryPolicy, now)
		if err := s.commit(p, rec, loaded, anchor); err != nil {
			return err
		}
		out = SendResult{Entry: entry, Created: true, Generation: rec.Generation, Burned: burned}
		crashAt(CrashSendAfterWrite)
		return nil
	})
	return out, err
}

// refuseWhileLatched keeps what this send learned about the latches and
// refuses it. The write is what makes a permit's list outlive the permit: the
// next permit may leave the account out, and that must not reopen sending.
//
// With both latches held the removal is reported: it is the one the app can
// least afford to misread, and either way nothing is encrypted.
func (s *Store) refuseWhileLatched(p convPaths, rec *Record, anchor Anchor, latch latches) error {
	if !latch.sameAs(rec) {
		loaded := rec.Generation
		latch.apply(rec)
		if err := s.commit(p, rec, loaded, anchor); err != nil {
			return err
		}
	}
	switch {
	case len(latch.removals) > 0:
		return ErrRotationPending
	case len(latch.devices) > 0:
		return ErrDeviceRevocationPending
	}
	return ErrLeafReplacementPending
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

// ErrSeqBound — MarkSent was asked to give a seq to a sent message when either
// side of the pair is already taken: the seq carries another message's copy,
// or the message was already bound to another seq. Rebinding would make a
// re-read of one seq answer with a different message's plaintext.
var ErrSeqBound = errors.New("chat state history already binds that seq or that message differently")

// MarkSentResult reports the binding. Bound is false when the entry already
// carried this seq and nothing was written.
type MarkSentResult struct {
	Bound      bool
	Generation uint64
}

// MarkSent binds a sent message's sealed copy to the seq the server assigned
// it, once POST /:id/messages has answered. From then on a display batch that
// names the seq is answered from the copy, the only place this device can read
// its own message from.
//
// Idempotent: the same pair again writes nothing. A copy that is gone — evicted
// by the ring or the age bound, or never made because the send predates this
// Keeper — is ErrNotFound, which leaves that message readable only as "sent
// from this device, no local copy".
func (s *Store) MarkSent(
	conversationID string, wm ServerWatermark, clientMessageID string, seq uint64,
) (MarkSentResult, error) {
	if clientMessageID == "" || seq == 0 {
		return MarkSentResult{}, errors.New("mark sent needs a client message id and a seq")
	}
	var out MarkSentResult
	err := s.withConversation(conversationID, func(p convPaths) error {
		rec, anchor, err := s.loadChecked(p, conversationID, wm)
		if err != nil {
			return err
		}
		i, ok := rec.findSentHistory(clientMessageID)
		if !ok {
			return ErrNotFound
		}
		if rec.History[i].Seq == seq {
			out = MarkSentResult{Generation: rec.Generation}
			return nil
		}
		if rec.History[i].Seq != 0 {
			return ErrSeqBound
		}
		if _, taken := rec.findHistory(seq); taken {
			return ErrSeqBound
		}
		loaded := rec.Generation
		rec.History[i].Seq = seq
		if err := s.commit(p, rec, loaded, anchor); err != nil {
			return err
		}
		out = MarkSentResult{Bound: true, Generation: rec.Generation}
		return nil
	})
	return out, err
}
