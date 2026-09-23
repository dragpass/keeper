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

// JoinFromEntryForTest is JoinFromPool from the pool entry on, for an entry
// the test hands in. It is how a test joins from an entry with no leaf
// recorded, which only a Keeper before 0.0.50 wrote and AddKeyPackages
// refuses to write.
func (s *Session) JoinFromEntryForTest(
	store *chatstate.Store, conversationID string, wm chatstate.ServerWatermark,
	welcome []byte, entry chatstate.KeyPackagePoolEntry, v LeafVerifier, now time.Time,
) error {
	return s.joinFromEntry(store, conversationID, wm, welcome, entry, v, now)
}

// StopAfterJoinedStateSavedForTest makes the next joins return err right
// after their group state is written and before the pool entry is deleted,
// which is where a crash would leave them, until restore is called.
func StopAfterJoinedStateSavedForTest(err error) (restore func()) {
	previous := afterJoinedStateSaved
	afterJoinedStateSaved = func() error { return err }
	return func() { afterJoinedStateSaved = previous }
}
