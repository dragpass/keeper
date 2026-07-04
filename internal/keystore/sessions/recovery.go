// recovery.go — Recovery old private key PEM opaque handle store.
//
// Background: applies the Group DEK opaque-handle pattern to the Recovery
// private key PEM, closing the carve-out where the PEM would otherwise
// surface in the Extension JS heap. Recovery is an emergency path outside
// the normal operation paths (drag / draglink / share); routing it through
// the opaque-handle store keeps the PEM inside Keeper memguard.
//
// Lifetime / Concurrency semantics: see the shared `Store` (store.go). This
// file only carries (1) RecoverySession-specific sentinel errors, (2) a
// wrapper type whose constructor injects a non-empty check, and (3)
// singleton + reaper-start helpers.
//
// All RecoverySessionStore methods are delegated to the embedded `*Store`;
// external caller signatures are unchanged.

package sessions

import (
	"errors"
	"time"
)

const (
	// RecoverySessionTTL — Recovery flows usually finish in < 1 minute, so the
	// TTL is kept short. (Unlike GroupSessionTTL's 15 minutes — Recovery is
	// triggered 0–1 times in a lifetime.)
	RecoverySessionTTL = 5 * time.Minute

	// RecoverySessionReaperInterval — sweep interval.
	RecoverySessionReaperInterval = 1 * time.Minute
)

var (
	ErrRecoverySessionNotFound = errors.New("recovery session handle not found")
	ErrRecoverySessionExpired  = errors.New("recovery session handle expired")
)

// RecoverySessionStore manages the handle ID → memguard-protected raw PEM
// mapping. It embeds the shared `Store` to expose all methods as-is. Since
// PEMs are variable-length, only a non-empty check is applied.
type RecoverySessionStore struct {
	*Store
}

// NewRecoverySessionStore builds a new store with the given TTL, injecting a
// non-empty check.
func NewRecoverySessionStore(ttl time.Duration) *RecoverySessionStore {
	return &RecoverySessionStore{
		Store: newStore(
			ttl,
			requireRecoveryPEMNonEmpty,
			ErrRecoverySessionNotFound,
			ErrRecoverySessionExpired,
		),
	}
}

// ────────────────────────────────────────────────────────────────────────
// Global singleton — used by the dispatcher in the Keeper main process.
// ────────────────────────────────────────────────────────────────────────

var defaultRecoverySessionStore = NewRecoverySessionStore(RecoverySessionTTL)

// DefaultRecoverySessionStore returns the singleton store inside the Keeper
// process.
func DefaultRecoverySessionStore() *RecoverySessionStore {
	return defaultRecoverySessionStore
}

// StartDefaultRecoverySessionReaper is invoked from main.go to start the
// reaper goroutine.
func StartDefaultRecoverySessionReaper() {
	defaultRecoverySessionStore.StartReaper(RecoverySessionReaperInterval)
}
