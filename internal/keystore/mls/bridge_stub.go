//go:build !mls || !cgo

// bridge_stub.go — what this package is when the MLS library is not linked.
//
// Every call answers ErrUnavailable rather than being absent, so callers
// compile once and branch on Available() instead of carrying their own build
// tags down the call chain.

package mls

// Session exists here only so the shared code in mls.go has a type to name.
type Session struct {
	leafFingerprint string
}

func Available() bool { return false }

func Version() (string, error) { return "", ErrUnavailable }

func openSession(identity, secretKey, publicKey, declaration []byte) (*Session, error) {
	return nil, ErrUnavailable
}

func (s *Session) approve(leaves []Leaf) error { return ErrUnavailable }

func (s *Session) approveRemovals(leaves []Leaf) error { return ErrUnavailable }

func (s *Session) processCollect(message []byte) ([]Leaf, CommitShape, error) {
	return nil, CommitShape{}, ErrUnavailable
}

func (s *Session) joinCollect(welcome []byte) ([]Leaf, error) { return nil, ErrUnavailable }

func keyPackageLeaf(keyPackage []byte) (Leaf, error) { return Leaf{}, ErrUnavailable }

func keyPackageNotAfter(keyPackage []byte) (uint64, error) { return 0, ErrUnavailable }

func WireFormOf(message []byte) (WireForm, error) { return WireFormOther, ErrUnavailable }

func (s *Session) Close() {}

func (s *Session) CreateGroup(groupID []byte) error { return ErrUnavailable }

func (s *Session) keyPackage(notAfterCap uint64) (message, reference, private []byte, err error) {
	return nil, nil, nil, ErrUnavailable
}

func (s *Session) installKeyPackage(private []byte) error { return ErrUnavailable }

func welcomeKeyPackageRefs(welcome []byte) ([][]byte, error) { return nil, ErrUnavailable }

func (s *Session) CommitAddMembers(keyPackages [][]byte) (commit, welcome []byte, expectedEpoch uint64, err error) {
	return nil, nil, 0, ErrUnavailable
}

func (s *Session) CommitUpdate() (commit []byte, expectedEpoch uint64, err error) {
	return nil, 0, ErrUnavailable
}

func (s *Session) CommitRemoveMembers(leafIndices []uint32) (commit []byte, expectedEpoch uint64, err error) {
	return nil, 0, ErrUnavailable
}

func (s *Session) CommitReplaceMembers(
	leafIndices []uint32, keyPackages [][]byte, authenticatedData []byte,
) (commit, welcome []byte, expectedEpoch uint64, err error) {
	return nil, nil, 0, ErrUnavailable
}

func (s *Session) Roster() ([]Leaf, error) { return nil, ErrUnavailable }

func (s *Session) ApplyPendingCommit() error { return ErrUnavailable }

func (s *Session) ClearPendingCommit() error { return ErrUnavailable }

func (s *Session) HasPendingCommit() (bool, error) { return false, ErrUnavailable }

func (s *Session) Epoch() (uint64, error) { return 0, ErrUnavailable }

func (s *Session) GroupID() ([]byte, error) { return nil, ErrUnavailable }

func (s *Session) Join(welcome []byte) error { return ErrUnavailable }

func (s *Session) Encrypt(plaintext, authenticatedData []byte) ([]byte, error) {
	return nil, ErrUnavailable
}

func (s *Session) Process(message []byte) (Processed, error) {
	return Processed{}, ErrUnavailable
}

func (s *Session) SendPosition() (epoch uint64, leafIndex, generation uint32, err error) {
	return 0, 0, 0, ErrUnavailable
}

func (s *Session) BurnGeneration() error { return ErrUnavailable }

func (s *Session) ExportSecret(label, context []byte, n int) ([]byte, error) {
	return nil, ErrUnavailable
}

func (s *Session) ExportPendingSecret(label, context []byte, n int) ([]byte, uint64, error) {
	return nil, 0, ErrUnavailable
}

func (s *Session) Flush() ([]byte, error) { return nil, ErrUnavailable }

func (s *Session) Load(blob []byte) error { return ErrUnavailable }
