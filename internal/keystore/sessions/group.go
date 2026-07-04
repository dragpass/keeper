// group.go — Group DEK opaque handle store.
//
// Background: closes the raw Group DEK Base64 residual surface (Extension's
// `RawGroupDekCache` with 5-minute TTL). The Keeper keeps the raw 32B Group
// DEK inside a memguard.LockedBuffer and only returns a 32B random handle ID
// (Base64) to the Extension. All subsequent aes_* actions reference the same
// key via the handle instead of raw bytes.
//
// Lifetime / Concurrency semantics: see the shared `Store` (store.go). This
// file only carries (1) GroupSession-specific sentinel errors, (2) a wrapper
// type whose constructor injects a 32B length check, and (3) singleton +
// reaper-start helpers.
//
// All GroupSessionStore methods (Open/Close/Use/Status/Size/SetClock/
// StartReaper/StopReaper/Reap) are delegated to the embedded `*Store`. The
// signatures of external callers (handlers / dispatcher / tests) are
// unchanged.

package sessions

import (
	"errors"
	"time"
)

const (
	// GroupSessionTTL — Keeper-side handle lifetime. Set longer than the
	// Extension-side TTL (5 minutes) so the reaper cleans up even when the
	// Extension forgets to issue an explicit close.
	GroupSessionTTL = 15 * time.Minute

	// GroupSessionReaperInterval — sweep interval for the reaper goroutine.
	GroupSessionReaperInterval = 1 * time.Minute
)

var (
	ErrGroupSessionNotFound = errors.New("group session handle not found")
	ErrGroupSessionExpired  = errors.New("group session handle expired")
)

// GroupSessionStore manages the handle ID → memguard-protected raw Group DEK
// mapping. It embeds the shared `Store` to expose all methods (Open/Close/Use/
// Status/Size/...) as-is.
type GroupSessionStore struct {
	*Store
}

// NewGroupSessionStore builds a new store with the given TTL, injecting a 32B
// length check. The reaper must be started separately (StartReaper).
func NewGroupSessionStore(ttl time.Duration) *GroupSessionStore {
	return &GroupSessionStore{
		Store: newStore(
			ttl,
			requireGroupDEKLen,
			ErrGroupSessionNotFound,
			ErrGroupSessionExpired,
		),
	}
}

// ────────────────────────────────────────────────────────────────────────
// Global singleton — used by the dispatcher in the Keeper main process.
// ────────────────────────────────────────────────────────────────────────

var defaultGroupSessionStore = NewGroupSessionStore(GroupSessionTTL)

// DefaultGroupSessionStore returns the singleton store inside the Keeper
// process. Used by dispatcher handlers. Tests should prefer
// NewGroupSessionStore to obtain an isolated instance.
func DefaultGroupSessionStore() *GroupSessionStore {
	return defaultGroupSessionStore
}

// StartDefaultGroupSessionReaper is invoked from main.go to start the reaper
// goroutine. Do not call from tests (prevents goroutine leaks).
func StartDefaultGroupSessionReaper() {
	defaultGroupSessionStore.StartReaper(GroupSessionReaperInterval)
}
