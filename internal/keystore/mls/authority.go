// authority.go — the Go half of the Commit authority rules: read what a
// Commit does off the collect pass, judge it (chatstate.JudgeReceived), and
// hand the Rust rules exactly the Removes that passed. The rules themselves
// are stated in chatstate/authority.go.

package mls

import (
	"github.com/dragpass/keeper/internal/keystore/chatstate"
)

// CommitShape is what the collect pass saw one message do. IsCommit is false
// for anything that is not a Commit. Removed holds each removed leaf as the
// tree held it before the Commit; Added holds each Add's leaf with index 0.
// Other lists every proposal type that is neither, a roles-only group context
// change aside. Epoch is the epoch the Commit applies to, RolesBefore that
// epoch's roles payload (nil: none), RolesChange and RolesAfter what the
// Commit does to them, and AuthenticatedData the Commit's own.
type CommitShape struct {
	IsCommit          bool
	Committer         uint32
	Removed           []Leaf
	Added             []Leaf
	Other             []uint16
	Epoch             uint64
	RolesBefore       []byte
	RolesChange       chatstate.RolesChangeKind
	RolesAfter        []byte
	AuthenticatedData []byte
}

// leaves reads one gate::encode_leaves list from where the reader stands.
func (r *leafReader) leaves() ([]Leaf, bool) {
	count, ok := r.u32()
	if !ok || count > maxLeaves {
		return nil, false
	}
	out := make([]Leaf, 0, count)
	for i := uint32(0); i < count; i++ {
		var l Leaf
		if l.Index, ok = r.u32(); !ok {
			return nil, false
		}
		if l.Identity, ok = r.prefixed(); !ok {
			return nil, false
		}
		if l.SignatureKey, ok = r.prefixed(); !ok {
			return nil, false
		}
		present, ok := r.take(1)
		if !ok {
			return nil, false
		}
		switch present[0] {
		case 0:
		case 1:
			if l.Declaration, ok = r.prefixed(); !ok {
				return nil, false
			}
			if l.Declaration == nil {
				l.Declaration = []byte{}
			}
		default:
			return nil, false
		}
		out = append(out, l)
	}
	return out, true
}

// commitChangeOf names a Commit's committer and every leaf it removes and adds
// by account. The committer is read from the tree the Commit was applied to,
// so it is the group's own statement of who signed it. An identity that is not
// a DragPass device identity is a refusal, never a leaf skipped over.
func commitChangeOf(shape CommitShape, before []Leaf) (chatstate.CommitChange, error) {
	var change chatstate.CommitChange
	found := false
	for _, l := range before {
		if l.Index != shape.Committer {
			continue
		}
		account, device, err := ParseCredentialIdentity(l.Identity)
		if err != nil {
			return chatstate.CommitChange{}, err
		}
		change.CommitterAccountID, change.CommitterDeviceID, found = account, device, true
	}
	if !found {
		return chatstate.CommitChange{}, failed("the committer is not a leaf of the group")
	}
	for _, l := range before {
		account, _, err := ParseCredentialIdentity(l.Identity)
		if err != nil {
			return chatstate.CommitChange{}, err
		}
		change.Before = append(change.Before, account)
		if l.Index == 0 {
			change.CreatorAccountID = account
		}
	}
	for _, l := range shape.Removed {
		account, device, err := ParseCredentialIdentity(l.Identity)
		if err != nil {
			return chatstate.CommitChange{}, err
		}
		change.Removed = append(change.Removed, account)
		change.RemovedLeaves = append(change.RemovedLeaves, chatstate.RemovedLeaf{
			AccountID: account, DeviceID: device, Declaration: l.Declaration,
		})
	}
	for _, l := range shape.Added {
		account, _, err := ParseCredentialIdentity(l.Identity)
		if err != nil {
			return chatstate.CommitChange{}, err
		}
		change.Added = append(change.Added, account)
	}
	change.OtherProposals = len(shape.Other)
	change.Epoch = shape.Epoch
	change.AuthenticatedData = shape.AuthenticatedData
	change.RolesChange = shape.RolesChange
	var err error
	if change.RolesBefore, err = parseRolesOrNil(shape.RolesBefore); err != nil {
		return chatstate.CommitChange{}, err
	}
	if shape.RolesChange == chatstate.RolesSet {
		if change.RolesAfter, err = parseRolesOrNil(shape.RolesAfter); err != nil || change.RolesAfter == nil {
			return chatstate.CommitChange{}, failed("the commit sets roles that do not parse")
		}
	}
	return change, nil
}

// parseRolesOrNil parses a roles payload, nil for none. A payload that does
// not parse is a failure: the group context either holds valid roles or none.
func parseRolesOrNil(payload []byte) (*chatstate.Roles, error) {
	if payload == nil {
		return nil, nil
	}
	roles, err := chatstate.ParseRoles(payload)
	if err != nil {
		return nil, failed("the group's roles do not parse")
	}
	return &roles, nil
}

// judgeCollected is the authority half of ProcessVerified: nothing for a
// message that is not a Commit, and for a Commit either a refusal or the
// Removes approved for the enforce pass that follows.
func (s *Session) judgeCollected(shape CommitShape, auth chatstate.CommitAuthority) (*chatstate.CommitChange, error) {
	if !shape.IsCommit {
		return nil, nil
	}
	before, err := s.Roster()
	if err != nil {
		return nil, err
	}
	change, err := commitChangeOf(shape, before)
	if err != nil {
		return nil, err
	}
	if err := chatstate.JudgeReceived(change, auth); err != nil {
		return nil, err
	}
	if err := judgeReceivedSuccession(shape, change); err != nil {
		return nil, err
	}
	if err := s.approveRemovals(shape.Removed); err != nil {
		return nil, err
	}
	return &change, nil
}
