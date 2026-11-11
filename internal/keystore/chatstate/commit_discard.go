// commit_discard.go — dropping this device's own pending Commit after the
// server definitively refused it (lv78, user decision 2026-11-11).
//
// # Why a fourth way out of a pending Commit
//
// The three outcomes in commit.go all follow from the epoch's verdict. A
// refusal is not a verdict about the epoch: the server answered that it will
// not take this Commit (a removal is pending in the conversation, the caller
// lost its authority, the room's owner is leaving, the member set moved) and
// stored nothing. A refusal alone does not prove that: the server checks
// access before it looks the Commit up, so a lost authority is also the
// answer to a Commit it took earlier; the handshake log check below decides.
// Left pending, the Commit is posted again by whatever the
// person does next, and once the reason for the refusal goes away it lands:
// a change the person was told was refused is applied later without anyone
// asking again. The app therefore drops it and rebuilds from the person's
// intent within the same action, or reports that the change was not applied.
//
// # What makes a discard safe
//
// Dropping a Commit that the server in fact accepted forks this device off
// the group: it no longer holds the secrets of the epoch its own Commit
// created. So the discard is narrow:
//
//   - it names the Commit by client_commit_id and the epoch it was built on,
//     and both must match the one pending Commit
//   - the group's confirmed epoch must still be that epoch, so no other
//     Commit has been applied since (applying one clears the pending anyway)
//   - the Commit must have been built under the chat login generation the
//     request runs under, so a discard decided in one sign-in never reaches a
//     Commit of the next
//   - the caller must have read the handshake log and found no row at the
//     next epoch. That is the server's word that this Commit did not take the
//     epoch; the store cannot check it, as it cannot check an "accepted"
//     verdict. A row there means accepted or superseded, never a discard.
//
// The confirmed state does not move: the group state written back is the one
// loaded with its pending slot cleared, as in refuseWinner.

package chatstate

import (
	"errors"
	"fmt"

	"github.com/dragpass/keeper/internal/keystore/secure"
)

// ErrRefusedDiscardStale — the discard runs under another chat login than
// the one the Commit was built under, or the Commit records none. Wraps
// ErrCommitMismatch: the request is about a Commit this session did not make.
var ErrRefusedDiscardStale = fmt.Errorf("chat state refused commit discard is from another sign-in: %w", ErrCommitMismatch)

// RefusedCommitDiscard names the pending Commit to drop.
type RefusedCommitDiscard struct {
	ClientCommitID string
	ExpectedEpoch  uint64

	// LoginGeneration is the chat login generation the request runs under,
	// read by the caller under the Keeper process lock.
	LoginGeneration string
}

// DiscardRefusedCommit drops the pending Commit req names after the server
// definitively refused it and its log showed no row at the next epoch. Every
// state other than exactly that Commit pending on an unmoved confirmed epoch,
// under the same sign-in, is refused and writes nothing.
func (s *Store) DiscardRefusedCommit(
	conversationID string, wm ServerWatermark, req RefusedCommitDiscard, cipher CommitCipher,
) (DiscardResult, error) {
	if req.ClientCommitID == "" {
		return DiscardResult{}, errors.New("discard needs a client commit id")
	}
	var out DiscardResult
	err := s.withConversation(conversationID, func(p convPaths) error {
		rec, anchor, err := s.loadChecked(p, conversationID, wm)
		if err != nil {
			return err
		}
		if rec.Pending == nil {
			return ErrNoPendingCommit
		}
		pending := *rec.Pending
		// A create (epoch 0) has its own way out, DiscardUnacceptedGroup,
		// which also drops the group it made.
		if pending.ClientCommitID != req.ClientCommitID || pending.ExpectedEpoch != req.ExpectedEpoch ||
			pending.ExpectedEpoch == 0 {
			return ErrCommitMismatch
		}
		if pending.LoginGeneration == "" || pending.LoginGeneration != req.LoginGeneration {
			return ErrRefusedDiscardStale
		}
		if err := cipher.Load(rec.GroupState); err != nil {
			return err
		}
		// The group's confirmed epoch, not Record.Epoch: only the MLS state
		// says which epoch the pending fork hangs off.
		epoch, err := cipher.Epoch()
		if err != nil {
			return err
		}
		if epoch != pending.ExpectedEpoch {
			return ErrCommitMismatch
		}
		if err := cipher.ClearPending(); err != nil {
			return err
		}
		state, err := cipher.State()
		if err != nil {
			return err
		}
		defer secure.Zeroize(state)
		loaded := rec.Generation
		rec.GroupState = state
		rec.Pending = nil
		if err := s.commit(p, rec, loaded, anchor); err != nil {
			return err
		}
		out = DiscardResult{Discarded: true, Generation: rec.Generation}
		return nil
	})
	return out, err
}
