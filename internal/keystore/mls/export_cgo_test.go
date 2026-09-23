//go:build mls && cgo

package mls

import (
	"time"

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
