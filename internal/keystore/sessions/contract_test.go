// SessionManager interface contract — polymorphic regression guard.
//
// Asserts in a single table that both implementations (GroupSessionStore,
// RecoverySessionStore) satisfy the same contract. When a new implementation
// (e.g. SecureViewerSessionStore) is added, registering one more line in
// makeManagers automatically applies every case.
//
// **Defects this test catches:**
//   - Any of Open/Use/Close/Status/Reap drifting in semantics between the two
//     stores
//   - A new method added to the SessionManager interface but only implemented
//     by one store (a semantic drift compile-time assertions cannot catch)
//   - Close becoming non-idempotent
//   - Expired handles returning nil or some other error instead of the
//     sentinel
package sessions

import (
	"errors"
	"testing"
	"time"
)

// managerCase represents one implementation fed into the contract test.
type managerCase struct {
	name        string
	make        func(now func() time.Time, ttl time.Duration) SessionManager
	notFoundErr error // domain sentinel
	expiredErr  error // domain sentinel
	// payload generator — Group is raw 32B, Recovery is arbitrary PEM bytes.
	payload func() []byte
}

func makeManagers() []managerCase {
	return []managerCase{
		{
			name: "GroupSessionStore",
			make: func(now func() time.Time, ttl time.Duration) SessionManager {
				s := NewGroupSessionStore(ttl)
				if now != nil {
					s.SetClock(now)
				}
				return s
			},
			notFoundErr: ErrGroupSessionNotFound,
			expiredErr:  ErrGroupSessionExpired,
			payload: func() []byte {
				// Group DEK must be exactly 32B.
				b := make([]byte, 32)
				for i := range b {
					b[i] = byte(i)
				}
				return b
			},
		},
		{
			name: "RecoverySessionStore",
			make: func(now func() time.Time, ttl time.Duration) SessionManager {
				s := NewRecoverySessionStore(ttl)
				if now != nil {
					s.SetClock(now)
				}
				return s
			},
			notFoundErr: ErrRecoverySessionNotFound,
			expiredErr:  ErrRecoverySessionExpired,
			payload: func() []byte {
				// PEM is variable-length bytes — use an arbitrary payload.
				return []byte("-----BEGIN FAKE-----\nABC\n-----END FAKE-----\n")
			},
		},
	}
}

// TestSessionManagerContract_OpenUseRoundTrip: verify that Open → Use's
// callback receives the same payload.
func TestSessionManagerContract_OpenUseRoundTrip(t *testing.T) {
	for _, c := range makeManagers() {
		t.Run(c.name, func(t *testing.T) {
			mgr := c.make(nil, 5*time.Minute)
			payload := c.payload()
			expected := append([]byte(nil), payload...) // keep a copy

			handle, _, err := mgr.Open(payload)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			if handle == "" {
				t.Fatalf("Open returned empty handle")
			}

			var seen []byte
			useErr := mgr.Use(handle, func(p []byte) error {
				seen = append([]byte(nil), p...)
				return nil
			})
			if useErr != nil {
				t.Fatalf("Use: %v", useErr)
			}
			if string(seen) != string(expected) {
				t.Fatalf("payload mismatch: want %q, got %q", expected, seen)
			}
		})
	}
}

// TestSessionManagerContract_UseUnknownHandle: Use on a missing handle
// returns the not-found sentinel.
func TestSessionManagerContract_UseUnknownHandle(t *testing.T) {
	for _, c := range makeManagers() {
		t.Run(c.name, func(t *testing.T) {
			mgr := c.make(nil, 5*time.Minute)

			err := mgr.Use("unknown-handle", func([]byte) error { return nil })
			if !errors.Is(err, c.notFoundErr) {
				t.Fatalf("expected %v, got %v", c.notFoundErr, err)
			}
		})
	}
}

// TestSessionManagerContract_ExpiredHandleEvicted: after TTL elapses, Use
// returns the expired sentinel and the entry is auto-destroyed. Verified
// deterministically with a fake clock.
func TestSessionManagerContract_ExpiredHandleEvicted(t *testing.T) {
	for _, c := range makeManagers() {
		t.Run(c.name, func(t *testing.T) {
			frozen := time.Unix(1_700_000_000, 0)
			now := frozen
			clock := func() time.Time { return now }
			mgr := c.make(clock, 60*time.Second)

			handle, _, err := mgr.Open(c.payload())
			if err != nil {
				t.Fatalf("Open: %v", err)
			}

			// advance past TTL
			now = frozen.Add(120 * time.Second)

			useErr := mgr.Use(handle, func([]byte) error { return nil })
			if !errors.Is(useErr, c.expiredErr) {
				t.Fatalf("expected %v, got %v", c.expiredErr, useErr)
			}

			// Once expired, Use evicted the entry, so a second Use is not-found.
			useErr2 := mgr.Use(handle, func([]byte) error { return nil })
			if !errors.Is(useErr2, c.notFoundErr) {
				t.Fatalf("expected not-found after expired evict, got %v", useErr2)
			}
		})
	}
}

// TestSessionManagerContract_CloseIdempotent: Close is idempotent — even a
// missing handle succeeds.
func TestSessionManagerContract_CloseIdempotent(t *testing.T) {
	for _, c := range makeManagers() {
		t.Run(c.name, func(t *testing.T) {
			mgr := c.make(nil, 5*time.Minute)

			// close on a missing handle — no panic / error.
			mgr.Close("nonexistent-handle")

			handle, _, err := mgr.Open(c.payload())
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			mgr.Close(handle)
			mgr.Close(handle) // close twice — idempotent

			// Subsequent Use is not-found.
			useErr := mgr.Use(handle, func([]byte) error { return nil })
			if !errors.Is(useErr, c.notFoundErr) {
				t.Fatalf("expected not-found after Close, got %v", useErr)
			}
		})
	}
}

// TestSessionManagerContract_StatusLazyEvictsExpired: on Status, an expired
// entry is lazy-evicted and (false, 0) is returned.
func TestSessionManagerContract_StatusLazyEvictsExpired(t *testing.T) {
	for _, c := range makeManagers() {
		t.Run(c.name, func(t *testing.T) {
			frozen := time.Unix(1_700_000_000, 0)
			now := frozen
			clock := func() time.Time { return now }
			mgr := c.make(clock, 30*time.Second)

			handle, _, err := mgr.Open(c.payload())
			if err != nil {
				t.Fatalf("Open: %v", err)
			}

			// While valid: exists=true and remaining > 0.
			exists, remaining := mgr.Status(handle)
			if !exists || remaining <= 0 {
				t.Fatalf("expected exists=true positive remaining, got (%v, %d)", exists, remaining)
			}

			// After TTL: Status performs lazy-evict.
			now = frozen.Add(60 * time.Second)
			exists2, remaining2 := mgr.Status(handle)
			if exists2 || remaining2 != 0 {
				t.Fatalf("expected (false, 0) after expiry, got (%v, %d)", exists2, remaining2)
			}
		})
	}
}

// TestSessionManagerContract_ReapRemovesExpiredOnly: Reap removes only
// expired entries and preserves live entries.
func TestSessionManagerContract_ReapRemovesExpiredOnly(t *testing.T) {
	for _, c := range makeManagers() {
		t.Run(c.name, func(t *testing.T) {
			frozen := time.Unix(1_700_000_000, 0)
			now := frozen
			clock := func() time.Time { return now }
			mgr := c.make(clock, 60*time.Second)

			// Register h1 first.
			h1, _, err := mgr.Open(c.payload())
			if err != nil {
				t.Fatalf("Open h1: %v", err)
			}

			// Advance 30s — h1 still alive.
			now = frozen.Add(30 * time.Second)

			// Register h2.
			h2, _, err := mgr.Open(c.payload())
			if err != nil {
				t.Fatalf("Open h2: %v", err)
			}

			// Advance another 35s → total 65s → only h1 expires (frozen+65s >
			// frozen+60s); h2 still alive (valid until frozen+30s+60s =
			// frozen+90s).
			now = frozen.Add(65 * time.Second)

			reaped := mgr.Reap()
			if reaped != 1 {
				t.Fatalf("expected 1 reaped entry (h1), got %d", reaped)
			}

			// h1 is not-found; h2 is still usable.
			if err := mgr.Use(h1, func([]byte) error { return nil }); !errors.Is(err, c.notFoundErr) {
				t.Fatalf("h1 expected not-found after Reap, got %v", err)
			}
			if err := mgr.Use(h2, func([]byte) error { return nil }); err != nil {
				t.Fatalf("h2 must still be usable, got %v", err)
			}
		})
	}
}
