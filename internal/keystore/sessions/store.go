// store.go — shared base for opaque-handle session stores.
//
// GroupSessionStore and RecoverySessionStore had identical structure
// differing only in the entry payload (`*memguard.LockedBuffer`) and
// sentinel-error names. They are unified into a shared `Store` struct, and
// the two existing types (GroupSessionStore / RecoverySessionStore) are kept
// as thin wrappers so external caller signatures (handlers / dispatcher /
// tests) remain unchanged.
//
// Differences absorbed:
//   - input validation: `validateInput func([]byte) error`
//     (group = exactly 32B / recovery = non-empty)
//   - sentinels: `errNotFound` / `errExpired` (per-group/recovery errors)
//   - reaper goroutine is identical — wrappers only delegate methods.
//
// **Concurrency / lifetime / lazy-evict semantics are exactly the same as
// the original two stores.**

package sessions

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sync"
	"time"

	"github.com/awnumar/memguard"
)

// handleByteLen — both stores use the same 32B random → Base64 44 chars.
const handleByteLen = 32

// secretEntry holds memguard-protected raw bytes + expiry time. Same shape
// for both dek and pem cases.
type secretEntry struct {
	secret    *memguard.LockedBuffer
	expiresAt time.Time
}

// Store is the shared base for opaque-handle session stores. The two existing
// types (GroupSessionStore / RecoverySessionStore) embed it to preserve
// external caller compatibility.
type Store struct {
	mu      sync.Mutex
	entries map[string]*secretEntry
	ttl     time.Duration
	now     func() time.Time

	// validate checks raw bytes length/content on Open. On failure, the error
	// is returned as-is.
	validate func([]byte) error

	// The two stores expose different sentinel error instances, so inject.
	errNotFound error
	errExpired  error

	reaperOnce sync.Once
	reaperStop chan struct{}
}

// newStore is the shared constructor called by the wrapper types
// (GroupSessionStore / RecoverySessionStore).
func newStore(ttl time.Duration, validate func([]byte) error, errNotFound, errExpired error) *Store {
	return &Store{
		entries:     make(map[string]*secretEntry),
		ttl:         ttl,
		now:         time.Now,
		validate:    validate,
		errNotFound: errNotFound,
		errExpired:  errExpired,
	}
}

// SetClock — test-only (deterministic expiry checks).
func (s *Store) SetClock(now func() time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.now = now
}

// StartReaper launches a goroutine that periodically sweeps expired entries.
// Protected by sync.Once — idempotent.
func (s *Store) StartReaper(interval time.Duration) {
	s.reaperOnce.Do(func() {
		s.mu.Lock()
		s.reaperStop = make(chan struct{})
		stop := s.reaperStop
		s.mu.Unlock()
		go s.reapLoop(interval, stop)
	})
}

// StopReaper — idempotent.
func (s *Store) StopReaper() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.reaperStop != nil {
		close(s.reaperStop)
		s.reaperStop = nil
	}
}

func (s *Store) reapLoop(interval time.Duration, stop chan struct{}) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.Reap()
		case <-stop:
			return
		}
	}
}

// Reap sweeps expired entries. Returns the number removed (for test asserts).
func (s *Store) Reap() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	removed := 0
	for id, entry := range s.entries {
		if now.After(entry.expiresAt) {
			entry.secret.Destroy()
			delete(s.entries, id)
			removed++
		}
	}
	return removed
}

// Open registers raw bytes in the store and issues a handle ID. The input
// raw is taken zero-copy by memguard.NewBufferFromBytes and wiped — from the
// caller's perspective, the raw bytes are no longer valid.
func (s *Store) Open(raw []byte) (string, time.Time, error) {
	if err := s.validate(raw); err != nil {
		return "", time.Time{}, err
	}

	idBytes := make([]byte, handleByteLen)
	if _, err := rand.Read(idBytes); err != nil {
		return "", time.Time{}, err
	}
	handleID := base64.StdEncoding.EncodeToString(idBytes)

	buf := memguard.NewBufferFromBytes(raw)

	s.mu.Lock()
	expiresAt := s.now().Add(s.ttl)
	s.entries[handleID] = &secretEntry{
		secret:    buf,
		expiresAt: expiresAt,
	}
	s.mu.Unlock()

	return handleID, expiresAt, nil
}

// Close destroys + deletes the handle. Idempotent.
func (s *Store) Close(handleID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if entry, ok := s.entries[handleID]; ok {
		entry.secret.Destroy()
		delete(s.entries, handleID)
	}
}

// Use runs fn over the raw bytes pointed to by the handle. fn runs while the
// mutex is held, so it must finish quickly and must not re-enter the store.
// Expired handles are immediately destroy + delete + ErrExpired.
func (s *Store) Use(handleID string, fn func(raw []byte) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, ok := s.entries[handleID]
	if !ok {
		return s.errNotFound
	}
	if s.now().After(entry.expiresAt) {
		entry.secret.Destroy()
		delete(s.entries, handleID)
		return s.errExpired
	}
	return fn(entry.secret.Bytes())
}

// Status returns handle existence + remaining TTL (ms). Expired handles are
// lazy-evicted.
func (s *Store) Status(handleID string) (bool, int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.entries[handleID]
	if !ok {
		return false, 0
	}
	remaining := entry.expiresAt.Sub(s.now())
	if remaining <= 0 {
		entry.secret.Destroy()
		delete(s.entries, handleID)
		return false, 0
	}
	return true, remaining.Milliseconds()
}

// Size — testing / observability.
func (s *Store) Size() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries)
}

// ────────────────────────────────────────────────────────────────────────
// validate helpers — injected from wrapper-type constructors
// ────────────────────────────────────────────────────────────────────────

// requireGroupDEKLen checks the 32B AES-256 key length.
func requireGroupDEKLen(raw []byte) error {
	if len(raw) != 32 {
		return errors.New("group dek must be 32 bytes")
	}
	return nil
}

// requireRecoveryPEMNonEmpty — PEMs are variable-length; only reject empty.
func requireRecoveryPEMNonEmpty(raw []byte) error {
	if len(raw) == 0 {
		return errors.New("recovery pem must not be empty")
	}
	return nil
}
