// syncblock.go — a received Commit this device refused (N3).
//
// A refused Commit is one bad row, not a broken state. Latching the whole
// conversation read-only on it would hand a malicious server, or one member's
// modified client, a way to lock every honest device out for good with a
// single Commit it can always produce. So the refusal is recorded as a block
// on that row instead:
//
//   - the Commit is not applied, and nothing is ever built or sent on top of
//     the state it would have produced: this device stays at its confirmed
//     epoch, and a send is refused (ErrSyncBlocked) while the block holds,
//     because who can read the next message is exactly what is in question;
//   - a later row cannot be applied either, since each handshake applies only
//     to the epoch after the confirmed one (ErrHandshakeSkipped);
//   - another, valid Commit for the same epoch is applied as usual and clears
//     the block, as does this device's own Commit for that epoch once the
//     server accepts it; so does the same row, re-judged, once what refused
//     it no longer does (a changed key the person has since verified);
//   - reading what was already opened keeps working.
//
// What stays a latch (NeedsRekey) is a real state problem: a rollback, a
// missing state, a watermark ahead, and a fork, where the server served for
// an epoch this device already confirmed another Commit than the one it
// applied there.
//
// Where it is kept: the block lives in the conversation's anchor, the keyring
// entry Anchor under config.ChatStateAnchorPrefix, as its sync_block field.
// Writing it changes nothing else there (generation, reserved ceiling, epoch,
// watermark, the rekey fields) and nothing in the state file: the file is not
// written on a refusal, except when this device's own pending Commit lost its
// epoch to the refused one, where the lost pending is dropped (ConfirmCommit)
// and the confirmed part of the state is written back unchanged.

package chatstate

import (
	"errors"
)

// ErrSyncBlocked — a received Commit was refused at the next epoch and has
// not been superseded by a valid one, so no new message may be encrypted
// until the block clears.
var ErrSyncBlocked = errors.New("chat state is stopped at a commit it refused; nothing new may be sent")

// Sync block causes.
const (
	SyncBlockUnauthorizedCommit = "unauthorized_commit"
	SyncBlockLeafUntrusted      = "leaf_untrusted"
)

// SyncBlock is the refused row: the epoch it would produce, why it was
// refused, who committed it as the group's own tree names it (empty when the
// refusal came before that was known), and which Commit it was.
type SyncBlock struct {
	Epoch              uint64 `json:"epoch"`
	Cause              string `json:"cause"`
	CommitterAccountID string `json:"committer_account_id,omitempty"`
	CommitterDeviceID  string `json:"committer_device_id,omitempty"`
	CommitHash         string `json:"commit_sha256"`
}

// RowRefusal is an error that refuses a received Commit on its merits: the
// authority rules (UnauthorizedCommitError) or the leaf check. Anything else
// (a malformed message, a storage failure) passes through unrecorded.
type RowRefusal interface {
	error
	RefusalCause() string
}

// RefusalCause makes UnauthorizedCommitError a RowRefusal.
func (e *UnauthorizedCommitError) RefusalCause() string { return SyncBlockUnauthorizedCommit }

// SyncBlockedError is the refusal from the operation that recorded the block,
// carrying it and the refusal itself.
type SyncBlockedError struct {
	Block SyncBlock
	Err   error
}

func (e *SyncBlockedError) Error() string {
	return "chat state refused the commit for epoch and stopped there: " + e.Err.Error()
}

func (e *SyncBlockedError) Unwrap() error { return e.Err }

// blockIfRefused records a block when err refuses the row on its merits, and
// passes any other error through.
func blockIfRefused(s *Store, p convPaths, anchor Anchor, err error, epoch uint64, commit []byte) error {
	var refusal RowRefusal
	if !errors.As(err, &refusal) {
		return err
	}
	block := SyncBlock{Epoch: epoch, Cause: refusal.RefusalCause(), CommitHash: commitHash(commit)}
	var unauthorized *UnauthorizedCommitError
	if errors.As(err, &unauthorized) {
		block.CommitterAccountID, block.CommitterDeviceID = unauthorized.CommitterAccountID, unauthorized.CommitterDeviceID
	}
	anchor.SyncBlock = &block
	if serr := saveAnchor(s.secrets, p.tag, anchor); serr != nil {
		return serr
	}
	return &SyncBlockedError{Block: block, Err: err}
}
