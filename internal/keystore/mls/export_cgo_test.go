//go:build mls && cgo

package mls

import (
	"time"

	"github.com/dragpass/keeper/internal/keystore/chatstate"
	"github.com/dragpass/keeper/internal/keystore/secure"
)

// OpenSessionForTest lets the external test package play a client no Keeper
// would build: one with a signer and declaration of the test's choosing.
var OpenSessionForTest = openSession

// KeyPackage is a test convenience: one KeyPackage at the full lifetime whose
// private entry goes straight back into this session, standing in for the
// owner's pool. It holds one entry at a time, as a real join does. Production
// code goes through KeyPackages and JoinFromPool.
func (s *Session) KeyPackage() ([]byte, error) {
	kp, _, private, err := s.keyPackage(uint64(time.Now().Add(10 * 365 * 24 * time.Hour).Unix()))
	if err != nil {
		return nil, err
	}
	defer secure.Zeroize(private)
	if err := s.installKeyPackage(private); err != nil {
		return nil, err
	}
	return kp, nil
}

// WelcomeKeyPackageRefsForTest names the KeyPackages a Welcome is addressed
// to, so a test can find the pool entry a join would take.
var WelcomeKeyPackageRefsForTest = welcomeKeyPackageRefs

// StopAfterJoinedStateSavedForTest makes the next joins return err right
// after their group state is written and before the pool entry is deleted,
// which is where a crash would leave them, until restore is called.
func StopAfterJoinedStateSavedForTest(err error) (restore func()) {
	previous := afterJoinedStateSaved
	afterJoinedStateSaved = func() error { return err }
	return func() { afterJoinedStateSaved = previous }
}

// ApproveRemovalsForTest hands the Rust rules removals the test chose, so a
// test can play a member whose client builds a Commit its Keeper's own rules
// would never approve.
func (s *Session) ApproveRemovalsForTest(leaves []Leaf) error { return s.approveRemovals(leaves) }

// SetNextCommitAADForTest sets the authenticated data the next Commit build
// carries, so a test can play a member whose client writes data its Keeper
// would never write.
func (s *Session) SetNextCommitAADForTest(aad []byte) error { return s.setNextCommitAAD(aad) }

// Persist flushes the session's group state into the conversation's record.
// It is a test convenience: production writes group state inside the
// chatstate transactions the MLS handlers run, never through a bare flush.
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
	defer secure.Zeroize(blob)
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
	defer secure.Zeroize(blob)
	return true, s.Load(blob)
}
