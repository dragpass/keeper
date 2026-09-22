//go:build !mls || !cgo

// bridge_stub.go — what this package is when the MLS library is not linked.
//
// Every call answers ErrUnavailable rather than being absent, so callers
// compile once and branch on Available() instead of carrying their own build
// tags down the call chain.

package mls

// Session exists here only so the shared code in mls.go has a type to name.
type Session struct{}

func Available() bool { return false }

func Version() (string, error) { return "", ErrUnavailable }

func GenerateSignatureKey() (secret, public []byte, err error) {
	return nil, nil, ErrUnavailable
}

func NewSession(identity, secretKey, publicKey []byte) (*Session, error) {
	return nil, ErrUnavailable
}

func WireFormOf(message []byte) (WireForm, error) { return WireFormOther, ErrUnavailable }

func (s *Session) Close() {}

func (s *Session) CreateGroup(groupID []byte) error { return ErrUnavailable }

func (s *Session) KeyPackage() ([]byte, error) { return nil, ErrUnavailable }

func (s *Session) AddMember(keyPackage []byte) (commit, welcome []byte, err error) {
	return nil, nil, ErrUnavailable
}

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

func (s *Session) Flush() ([]byte, error) { return nil, ErrUnavailable }

func (s *Session) Load(blob []byte) error { return ErrUnavailable }
