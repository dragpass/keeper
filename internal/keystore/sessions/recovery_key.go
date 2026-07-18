package sessions

import (
	"errors"
	"time"

	"github.com/dragpass/keeper/internal/keystore/recoverykey"
)

const (
	RecoveryKeySessionTTL            = 5 * time.Minute
	RecoveryKeySessionReaperInterval = 1 * time.Minute
)

var (
	ErrRecoveryKeySessionNotFound = errors.New("recovery key handle not found")
	ErrRecoveryKeySessionExpired  = errors.New("recovery key handle expired")
)

type RecoveryKeySessionStore struct {
	*Store
}

func NewRecoveryKeySessionStore(ttl time.Duration) *RecoveryKeySessionStore {
	return &RecoveryKeySessionStore{Store: newStore(
		ttl,
		requireRecoveryKey,
		ErrRecoveryKeySessionNotFound,
		ErrRecoveryKeySessionExpired,
	)}
}

func requireRecoveryKey(raw []byte) error {
	normalized, err := recoverykey.Normalize(raw)
	if normalized != nil {
		for i := range normalized {
			normalized[i] = 0
		}
	}
	return err
}

var defaultRecoveryKeySessionStore = NewRecoveryKeySessionStore(RecoveryKeySessionTTL)

func DefaultRecoveryKeySessionStore() *RecoveryKeySessionStore {
	return defaultRecoveryKeySessionStore
}

func StartDefaultRecoveryKeySessionReaper() {
	defaultRecoveryKeySessionStore.StartReaper(RecoveryKeySessionReaperInterval)
}
