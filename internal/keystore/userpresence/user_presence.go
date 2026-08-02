// Package userpresence defines the trusted local recovery-key display boundary.
package userpresence

import (
	"context"
	"errors"
	"time"

	"github.com/awnumar/memguard"
)

var (
	ErrUnavailable = errors.New("user presence is unavailable")
	ErrDenied      = errors.New("user presence denied")
	ErrTimedOut    = errors.New("user presence timed out")
	ErrEmptySecret = errors.New("secret must not be empty")
)

type Capabilities struct {
	Available       bool
	ShowRecoveryKey bool
	Backend         string
}

type RecoveryKeyPrompt struct {
	Title       string
	Message     string
	RecoveryKey *memguard.LockedBuffer
	Timeout     time.Duration
}

// UserPresence is the only interface through which handlers may display a
// recovery key. Implementations must not pass it through a shell command,
// argv, environment variables, or logs.
type UserPresence interface {
	Capabilities() Capabilities
	ShowRecoveryKey(context.Context, RecoveryKeyPrompt) error
}

// Unavailable is the fail-closed default until a platform-native backend is
// wired by the production binary.
type Unavailable struct{}

func (Unavailable) Capabilities() Capabilities {
	return Capabilities{Backend: "unavailable"}
}

func (Unavailable) ShowRecoveryKey(context.Context, RecoveryKeyPrompt) error {
	return ErrUnavailable
}
