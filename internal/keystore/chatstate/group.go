// group.go — the two ways a conversation gets its first group state: creating
// the group here, and joining one somebody else created.

package chatstate

import (
	"errors"
)

// ErrGroupExists — the conversation already holds a group, or a Commit that
// would create one. Creating a second group over it would throw away the
// state the first one's members are encrypting to.
var ErrGroupExists = errors.New("chat state already holds a group for this conversation")

// GroupCreator is CommitCipher plus the one call that makes a group out of
// nothing. The group is created inside the same locked section that builds its
// first Commit, so there is no moment at which a group exists on disk with
// nobody in it but its creator.
type GroupCreator interface {
	CommitCipher

	// CreateGroup starts a group at epoch 0 holding only this device.
	CreateGroup(groupID []byte) error
}

// CreateGroup creates the conversation's group and builds the Add that brings
// its first members in, leaving that Add pending (§7.3) exactly as BeginCommit
// leaves any other Commit.
//
// One transaction and one file replacement, which is what makes a refusal
// persist nothing: a KeyPackage that fails §5.3 fails the build, and the group
// that was created in memory for it is dropped with the session. The other
// order — persist the empty group, then BeginCommit — would leave an epoch-0
// group behind every refused create, and the next attempt would find it and
// refuse with ErrGroupExists.
//
// A retry with the same client commit id answers from the stored pending
// Commit, the way BeginCommit does, so a lost response is not a second group.
func (s *Store) CreateGroup(
	conversationID string, wm ServerWatermark, req BeginCommitRequest, cipher GroupCreator,
) (BeginCommitResult, error) {
	if req.ClientCommitID == "" {
		return BeginCommitResult{}, errors.New("commit needs a client commit id")
	}
	if len(req.Plan.AddKeyPackages) == 0 || len(req.Plan.RemoveAccountIDs) > 0 || len(req.Plan.Replace) > 0 {
		return BeginCommitResult{}, errors.New("a group is created by adding members and nothing else")
	}
	if err := checkRoomName(req.RoomName); err != nil {
		return BeginCommitResult{}, err
	}
	var out BeginCommitResult
	err := s.withConversation(conversationID, func(p convPaths) error {
		rec, anchor, err := s.loadChecked(p, conversationID, wm)
		if err != nil {
			return err
		}
		if rec.Pending != nil && rec.Pending.ClientCommitID == req.ClientCommitID {
			name, err := resealPending(conversationID, rec, req.RoomName, cipher)
			if err != nil {
				return err
			}
			out = pendingResult(*rec.Pending, rec.Generation, false)
			out.RoomName = name
			return nil
		}
		if rec.Pending != nil || len(rec.GroupState) > 0 {
			return ErrGroupExists
		}
		if err := cipher.CreateGroup([]byte(conversationID)); err != nil {
			return err
		}
		built, err := cipher.BuildCommit(req.Plan)
		if err != nil {
			return err
		}
		if len(built.Commit) == 0 || len(built.Commit) > MaxCommitBytes ||
			len(built.Welcome) == 0 || len(built.Welcome) > MaxCommitBytes {
			return errors.New("mls commit or welcome is outside the size bound")
		}
		state, err := cipher.State()
		if err != nil {
			return err
		}
		var name *SealedRoomName
		if req.RoomName != nil {
			if name, err = sealForPending(cipher, conversationID, built.ExpectedEpoch, req.RoomName); err != nil {
				return err
			}
		}
		pending := PendingCommit{
			ClientCommitID: req.ClientCommitID,
			ExpectedEpoch:  built.ExpectedEpoch,
			Commit:         built.Commit,
			Welcome:        built.Welcome,
		}
		loaded := rec.Generation
		rec.GroupState = state
		rec.Pending = &pending
		if err := s.commit(p, rec, loaded, anchor); err != nil {
			return err
		}
		out = pendingResult(pending, rec.Generation, true)
		out.RoomName = name
		return nil
	})
	return out, err
}

// SaveJoinedGroupState stores the group a Welcome produced, and moves the
// record onto the epoch the group joined at.
//
// SaveGroupState leaves Record.Epoch alone, which is right for a blob that has
// not moved the confirmed epoch and wrong for a join: a joiner enters at the
// committer's epoch, and a record left at 0 would report that — and judge the
// anchor against it — until the first send or delivery corrected it.
//
// A pending Commit refuses the join. Replacing the group state under it would
// leave a record that says a Commit is waiting on a group that no longer holds
// it.
func (s *Store) SaveJoinedGroupState(
	conversationID string, wm ServerWatermark, blob []byte, epoch uint64,
) (uint64, error) {
	if len(blob) == 0 {
		return 0, errors.New("group state blob is empty")
	}
	var generation uint64
	err := s.withConversation(conversationID, func(p convPaths) error {
		rec, anchor, err := s.loadChecked(p, conversationID, wm)
		if err != nil {
			return err
		}
		if rec.Pending != nil {
			return ErrCommitPending
		}
		loaded := rec.Generation
		rec.GroupState = blob
		rec.enterEpoch(epoch)
		if err := s.commit(p, rec, loaded, anchor); err != nil {
			return err
		}
		generation = rec.Generation
		return nil
	})
	return generation, err
}

// ErrNotUnacceptedCreate — the conversation holds a group that is not this
// device's own create still waiting on its first verdict. Discarding it would
// throw away state someone else may be encrypting to.
var ErrNotUnacceptedCreate = errors.New("chat state group is not an unaccepted create of this device")

// DiscardResult reports what DiscardUnacceptedGroup did. Discarded is false
// when there was nothing left to discard and nothing was written.
type DiscardResult struct {
	Discarded  bool
	Generation uint64
}

// DiscardUnacceptedGroup drops a group this device created whose create
// Commit was never accepted, so the device can join the group that won
// instead. Two members opening the same DM at once each create a group under
// the one conversation id; the server accepts one create, and the loser's
// stays pending with nothing in the protocol able to settle it — the winner's
// Commit belongs to another group and does not apply. Until this runs, the
// pending create refuses the join (SaveJoinedGroupState).
//
// It succeeds only on exactly that state: the pending Commit is the one named,
// it was built against epoch 0, and the record has never been confirmed past
// epoch 0. CreateGroup is the only thing that writes that pair — a join enters
// at the committer's epoch, which is at least 1, and every other Commit is
// built against a confirmed epoch of at least 1 — so the group was created on
// this device. Everything else is refused.
//
// Why this cannot discard real state: until a create is accepted, the group
// exists on this device and nowhere else. Its Welcome is released only for an
// accepted row (RFC 9420 §14), so no member ever joined it; its only member is
// this device, and nothing was encrypted in it, because a send is refused
// while a Commit is pending and epoch 0 has nobody to send to. Dropping it
// loses no message and consumes no key anyone else holds. What the Keeper
// cannot check is the server's verdict itself: a create the server did accept
// but whose answer was lost looks the same from here. That is why the caller
// must have seen the server give the epoch to another create before calling
// this, and ask by client_commit_id when it is unsure.
//
// Idempotent: a record with no group and no pending Commit has nothing to
// discard and answers Discarded false. The latches and every other field stay
// as they are.
func (s *Store) DiscardUnacceptedGroup(
	conversationID string, wm ServerWatermark, clientCommitID string,
) (DiscardResult, error) {
	if clientCommitID == "" {
		return DiscardResult{}, errors.New("discard needs a client commit id")
	}
	var out DiscardResult
	err := s.withConversation(conversationID, func(p convPaths) error {
		rec, anchor, err := s.loadChecked(p, conversationID, wm)
		if err != nil {
			return err
		}
		if rec.Pending == nil && len(rec.GroupState) == 0 {
			out = DiscardResult{Generation: rec.Generation}
			return nil
		}
		if rec.Pending == nil {
			return ErrNotUnacceptedCreate
		}
		if rec.Pending.ClientCommitID != clientCommitID {
			return ErrCommitMismatch
		}
		if rec.Pending.ExpectedEpoch != 0 || rec.Epoch != 0 {
			return ErrNotUnacceptedCreate
		}
		loaded := rec.Generation
		rec.GroupState = nil
		rec.Pending = nil
		if err := s.commit(p, rec, loaded, anchor); err != nil {
			return err
		}
		out = DiscardResult{Discarded: true, Generation: rec.Generation}
		return nil
	})
	return out, err
}
