// static_chain_test.go — the pre-MLS static-chain operations, kept as test
// fixtures.
//
// chat_state_reserve_send, chat_state_commit_outbox and
// chat_state_mark_received were removed from the wire once mls_encrypt and the
// receive path started consuming and marking positions themselves. The store
// operations behind them run the same locked load / judge / commit cycle as
// every production operation, so the anchor, rollback and cross-process lock
// tests keep driving that cycle through them.

package chatstate

import (
	"errors"
	"fmt"
)

// ErrPositionNotReserved — the position sits at or beyond the sending
// chain's high-water mark, so nothing ever handed it out.
var ErrPositionNotReserved = errors.New("chain position was not reserved")

// MaxReserveCount bounds one reservation. A caller that wants more positions
// than this is not composing a message.
const MaxReserveCount = 64

// Reservation is the answer to "which positions may I encrypt with". It is
// returned only after the consumption of those positions is on disk and
// fsynced, so a crash between this answer and the encryption loses a message
// and never reuses a position. A gap in the chain is ordinary; a repeat is not
// recoverable.
type Reservation struct {
	Epoch           uint64
	FirstChainIndex uint64
	Count           int
	Generation      uint64
}

// Reserve consumes count chain positions and returns them. The consumption is
// durable before this returns; see Reservation.
func (s *Store) Reserve(conversationID string, count int, wm ServerWatermark) (Reservation, error) {
	if count < 1 || count > MaxReserveCount {
		return Reservation{}, fmt.Errorf("reserve count must be 1..%d", MaxReserveCount)
	}
	var out Reservation
	err := s.withConversation(conversationID, func(p convPaths) error {
		rec, anchor, err := s.loadCheckedStatic(p, conversationID, wm)
		if err != nil {
			return err
		}
		if anchor.SyncBlock != nil {
			return ErrSyncBlocked
		}
		loaded := rec.Generation
		first := rec.NextIndex
		need := first + uint64(count)
		anchor.ReservedBefore = max(anchor.ReservedBefore, need)
		if err := saveAnchor(s.secrets, p.tag, anchor); err != nil {
			return err
		}
		rec.NextIndex = need
		if err := s.commit(p, rec, loaded, anchor); err != nil {
			return err
		}
		out = Reservation{
			Epoch:           rec.Epoch,
			FirstChainIndex: first,
			Count:           count,
			Generation:      rec.Generation,
		}
		return nil
	})
	return out, err
}

// CommitOutbox stores the ciphertext built for a reserved position. The stored
// entry is authoritative: a second call with the same client message id returns
// what is already there and writes nothing, so a retransmission after a lost
// response is the same bytes rather than a second encryption.
func (s *Store) CommitOutbox(
	conversationID string, wm ServerWatermark, entry OutboxEntry,
) (OutboxEntry, bool, error) {
	if len(entry.IV) != ivBytes ||
		len(entry.Ciphertext) == 0 || len(entry.Ciphertext) > MaxCiphertextBytes {
		return OutboxEntry{}, false, errors.New("outbox entry has an unusable ciphertext")
	}
	var (
		stored  OutboxEntry
		created bool
	)
	err := s.withConversation(conversationID, func(p convPaths) error {
		rec, anchor, err := s.loadCheckedStatic(p, conversationID, wm)
		if err != nil {
			return err
		}
		if existing, ok := rec.findOutbox(entry.ClientMessageID); ok {
			stored, created = existing, false
			return nil
		}
		if entry.Position.Epoch != rec.Epoch || entry.Position.Generation >= rec.NextIndex {
			return ErrPositionNotReserved
		}
		if rec.positionTaken(entry.Position) || rec.sealedBySendPath(entry.Position) {
			return ErrPositionTaken
		}
		loaded := rec.Generation
		rec.appendOutbox(entry)
		if err := s.commit(p, rec, loaded, anchor); err != nil {
			return err
		}
		stored, created = entry, true
		return nil
	})
	return stored, created, err
}

// MarkReceived records an inbound position and reports whether this delivery
// was the first. Persisting the mark before the caller is told it may show the
// message is what keeps a redelivery from advancing the state twice.
//
// A position that does not name its ratchet is refused rather than stored: an
// unnamed axis collapses two senders' chains onto one key, and the answer this
// returns would then be "redelivery" for a message nobody has seen.
func (s *Store) MarkReceived(
	conversationID string, wm ServerWatermark, pos Position,
) (bool, uint64, error) {
	if !pos.ContentType.valid() {
		return false, 0, errors.New("received position must name a content type")
	}
	var (
		first      bool
		generation uint64
	)
	err := s.withConversation(conversationID, func(p convPaths) error {
		rec, anchor, err := s.loadCheckedStatic(p, conversationID, wm)
		if err != nil {
			return err
		}
		if rec.receivedContains(pos) {
			first, generation = false, rec.Generation
			return nil
		}
		loaded := rec.Generation
		rec.appendReceived(pos)
		if err := s.commit(p, rec, loaded, anchor); err != nil {
			return err
		}
		first, generation = true, rec.Generation
		return nil
	})
	return first, generation, err
}

// loadCheckedStatic is loadChecked for the actions that send on the account's
// static chain: an untouched record still judges the account's watermark as
// its own, as before MLS.
func (s *Store) loadCheckedStatic(
	p convPaths, conversationID string, wm ServerWatermark,
) (*Record, Anchor, error) {
	rec, anchor, err := s.loadLocal(p, conversationID)
	if err != nil {
		return nil, anchor, err
	}
	rec.staticChain = true
	checked, anchor, err := s.judgeWatermark(p, rec, anchor, wm)
	if checked != nil {
		checked.staticChain = false
	}
	return checked, anchor, err
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
