// Package userpresence defines the trusted local UI boundary used for
// password, recovery-key, and approval prompts.
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
	PromptSecret    bool
	Confirm         bool
	ShowRecoveryKey bool
	Backend         string
}

type SecretPrompt struct {
	Title   string
	Message string
	Label   string
	Timeout time.Duration
}

type SecretResult struct {
	// Secret ownership transfers to the caller, which must Destroy it.
	Secret *memguard.LockedBuffer
}

type ConfirmPrompt struct {
	Title       string
	Message     string
	ApproveText string
	DenyText    string
	Timeout     time.Duration
}

type Decision string

const (
	DecisionApprove Decision = "approve"
	DecisionDeny    Decision = "deny"
)

type RecoveryKeyPrompt struct {
	Title       string
	Message     string
	RecoveryKey *memguard.LockedBuffer
	Timeout     time.Duration
}

// UserPresence is the only interface through which handlers may request
// trusted local input or confirmation. Implementations must not pass secrets
// through a shell command, argv, environment variables, or logs.
type UserPresence interface {
	Capabilities() Capabilities
	PromptSecret(context.Context, SecretPrompt) (SecretResult, error)
	Confirm(context.Context, ConfirmPrompt) (Decision, error)
	ShowRecoveryKey(context.Context, RecoveryKeyPrompt) error
}

// Unavailable is the fail-closed default until a platform-native backend is
// wired by the production binary.
type Unavailable struct{}

func (Unavailable) Capabilities() Capabilities {
	return Capabilities{Backend: "unavailable"}
}

func (Unavailable) PromptSecret(context.Context, SecretPrompt) (SecretResult, error) {
	return SecretResult{}, ErrUnavailable
}

func (Unavailable) Confirm(context.Context, ConfirmPrompt) (Decision, error) {
	return "", ErrUnavailable
}

func (Unavailable) ShowRecoveryKey(context.Context, RecoveryKeyPrompt) error {
	return ErrUnavailable
}
