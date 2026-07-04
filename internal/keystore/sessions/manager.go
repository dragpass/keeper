// Package sessions — Session Manager Boundary.
//
// **Goal:** keep stores that hide short-lived secrets (raw 32B Group DEK with
// short TTL / old private key PEM / future secure-viewer contexts) behind
// opaque handles aligned on the same interface contract. During public review
// you can verify in one place: "Do different stores share the same API? Are
// expiry / reaping / idempotent close behaviors consistent?"
//
// **Current implementations:**
//
//   - GroupSessionStore   (raw 32B Group DEK)
//   - RecoverySessionStore (old RSA private key PEM bytes)
//
// **Future additions:**
//
//   - SecureViewerSessionStore (one-shot plaintext snapshot for audit mode, etc.)
//
// When adding a new implementation, lock in interface conformance via a
// compile-time assertion in this file and add one row to the polymorphic
// table test in session_manager_contract_test.go.
package sessions

import "time"

// SessionManager is the common contract for stores that manage short-TTL
// payloads behind opaque handles.
//
// **Invariants (all implementations):**
//
//  1. **Open** takes ownership of the input payload's backing memory; after
//     the call the caller must not assume the payload is still valid
//     (memguard transfer). Once Open succeeds, the returned handle is valid
//     until Close or Reap.
//  2. **Use** runs the callback over the payload pointed to by the handle.
//     The store holds the mutex while the callback runs, so re-entering the
//     store API from the callback (another Open/Use/Close) will deadlock.
//     Callbacks must finish quickly.
//  3. **Expired handles** are auto-destroyed + deleted by Use and rejected
//     with a sentinel error. `errors.Is(err, ...)` matching uses domain
//     sentinels, but the Error Taxonomy's `CodeForError` maps both to
//     `ErrCodeExpiredSession`.
//  4. **Close** is idempotent. Closing a missing handle does not error.
//  5. **Status** lazy-evicts expired handles and returns (exists, remainingMs).
//     Returns (false, 0) when absent.
//  6. **Reap** destroys expired entries in bulk and returns the count. Can be
//     invoked deterministically from fake-clock unit tests.
//
// **Return signature:** the payload type for `Open` / `Use` is `[]byte`. The
// caller decides inside the callback whether it is a 32B Group DEK or PEM
// bytes.
type SessionManager interface {
	// Open registers payload bytes under a fresh handle ID. Returns
	// (handleID, expiresAt, error). The payload's backing memory is
	// transferred to the manager (memguard); the caller must not retain
	// references to the slice.
	Open(payload []byte) (string, time.Time, error)

	// Use invokes fn with the live payload bytes (held in memguard) for the
	// given handle. If the handle is missing or expired, returns the
	// implementation's sentinel error (errors.Is matches the domain-specific
	// sentinel; CodeForError converges to ErrCodeNotFound / ErrCodeExpiredSession).
	Use(handleID string, fn func(payload []byte) error) error

	// Close destroys the entry for handleID. Idempotent — calling Close on
	// an unknown or already-closed handle is a no-op.
	Close(handleID string)

	// Status returns (exists, remainingMs). Lazy-evicts expired entries.
	// remainingMs is 0 for missing or just-evicted handles.
	Status(handleID string) (bool, int64)

	// Reap destroys all expired entries and returns the count reaped.
	// Safe to call concurrently with Open/Close/Use; expired entries removed
	// during a Reap pass do not affect concurrent Use calls (they receive
	// the sentinel error).
	Reap() int
}

// Compile-time assertions — when a new store is added, the build confirms it
// satisfies the interface contract. If an interface change leaves only one of
// the two stores conforming, the build fails.
var (
	_ SessionManager = (*GroupSessionStore)(nil)
	_ SessionManager = (*RecoverySessionStore)(nil)
)
