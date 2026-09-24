// status.go — what a conversation's record says, without changing it.

package chatstate

import (
	"errors"
)

// ConversationStatus is what the app needs to know before it tries to send:
// where the group is, whether a Commit is waiting, whether the S-1 latch would
// refuse, and whether the record is latched for a rewind. Nothing in it is a
// secret or derived from one.
type ConversationStatus struct {
	// Epoch is the confirmed epoch, never one a pending Commit would reach.
	Epoch         uint64
	HasGroupState bool

	CommitPending         bool
	PendingClientCommitID string

	// PendingAppContext is PendingCommit.AppContext, nil when no Commit is
	// pending or the pending one was built without it.
	PendingAppContext []byte

	// PendingName is the room name the pending Commit's first build sealed,
	// nil when there is none.
	PendingName *SealedRoomName

	// RemovalLatch is what a send would be judged against now: the stored
	// latch plus the permit's list, kept where the confirmed roster still
	// holds the account. Sorted, and empty rather than nil.
	RemovalLatch []string

	// LeafReplacementLatch is the same for the M4.4 latch: what a send would
	// be refused for now with ErrLeafReplacementPending. Empty rather than
	// nil.
	LeafReplacementLatch []LeafReplacement

	// DeviceRevokeLatch is the same for the device revocation latch.
	DeviceRevokeLatch []DeviceRef

	// RemovedFromGroup is Record.RemovedFromGroup: the last Commit applied to
	// the confirmed state removed this device, so ForgetRemovedGroup must run
	// before a Welcome is joined. Reported so a caller that restarted, and no
	// longer holds the removed answer it was given, can still keep that order.
	RemovedFromGroup bool

	// NeedsRekey is the rewind latch. When it is set nothing else is read:
	// the record behind it is not trusted to say anything.
	NeedsRekey bool

	// RekeyCause is why NeedsRekey latched, and "" when it is not latched or
	// the latch predates the cause being recorded.
	RekeyCause RekeyCause

	// RekeyEpoch and RekeyCommitter* are the latch's detail for
	// unauthorized_commit and fork (Anchor.RekeyEpoch), zero otherwise.
	RekeyEpoch              uint64
	RekeyCommitterAccountID string
	RekeyCommitterDeviceID  string
}

// StatusCipher is what Status needs from MLS: the confirmed roster, to judge
// the permit's lists the way the next send would.
type StatusCipher interface {
	Load(groupState []byte) error
	RosterReader
}

// Status reports the conversation's state and writes nothing of its own.
//
// It goes through the same rollback judgement as every other read here, so a
// record that turns out to be rewound is latched by the read that found it,
// as ReadOutbox and LoadGroupState do; answering "fine" for a rewound record
// and letting the next send latch it would be the one wrong answer. The latch
// it reports is computed and not stored: persisting what the permit named is
// the send's job (refuseWhileLatched), and a status read has no position to
// refuse.
func (s *Store) Status(conversationID string, wm ServerWatermark, cipher StatusCipher) (ConversationStatus, error) {
	out := ConversationStatus{
		RemovalLatch: []string{}, LeafReplacementLatch: []LeafReplacement{}, DeviceRevokeLatch: []DeviceRef{},
	}
	err := s.withConversation(conversationID, func(p convPaths) error {
		rec, _, err := s.loadChecked(p, conversationID, wm)
		if errors.Is(err, ErrRekeyRequired) {
			out.NeedsRekey = true
			detail, err := s.rekeyDetail(p)
			out.RekeyCause, out.RekeyEpoch = detail.Cause, detail.Epoch
			out.RekeyCommitterAccountID, out.RekeyCommitterDeviceID = detail.CommitterAccountID, detail.CommitterDeviceID
			return err
		}
		if err != nil {
			return err
		}
		out.Epoch = rec.Epoch
		out.HasGroupState = len(rec.GroupState) > 0
		out.RemovedFromGroup = rec.RemovedFromGroup
		if rec.Pending != nil {
			out.CommitPending = true
			out.PendingClientCommitID = rec.Pending.ClientCommitID
			out.PendingAppContext = rec.Pending.AppContext
			if name := rec.Pending.Name; name != nil {
				out.PendingName = &SealedRoomName{
					Epoch: rec.Pending.ExpectedEpoch + 1, IV: name.IV, Ciphertext: name.Ciphertext,
				}
			}
		}
		latch := storedLatches(rec)
		if out.HasGroupState && (latch.held() ||
			len(wm.PendingRemovals) > 0 || len(wm.PendingLeafReplacements) > 0 ||
			len(wm.PendingDeviceRevocations) > 0) {
			if err := cipher.Load(rec.GroupState); err != nil {
				return err
			}
			if latch, err = judgeLatches(rec, wm, cipher); err != nil {
				return err
			}
		}
		out.RemovalLatch = append(out.RemovalLatch, latch.removals...)
		out.LeafReplacementLatch = append(out.LeafReplacementLatch, latch.expected()...)
		out.DeviceRevokeLatch = append(out.DeviceRevokeLatch, latch.devices...)
		return nil
	})
	return out, err
}
