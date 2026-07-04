// Package clipboard — Keeper-owned OS clipboard abstraction.
//
// Initial wiring: interface + Noop (production default) + Memory (test fake).
// The real OS clipboard impl (`golang.design/x/clipboard`, etc.) is
// introduced in a follow-up phase. This phase only sets up Deps injection +
// handler dispatch + regression guards.
//
// See security/keeper-plaintext-command-api-plan.md "Design decisions".
package clipboard

import (
	"crypto/sha256"
	"errors"
	"sync"
	"time"
)

// ErrUnavailable means Keeper could not initialize an OS clipboard backend.
// Callers must surface this as a copy failure instead of pretending success.
var ErrUnavailable = errors.New("clipboard unavailable")

// Clipboard is the Keeper-owned OS clipboard abstraction.
//
// `Write(plaintext, ttl)` writes plaintext to the clipboard and keeps the
// SHA-256 hash internally for compare-then-clear at TTL expiry. The caller
// can zeroize `plaintext` immediately after the call. The interface never
// returns plaintext back to the caller — a structural guard against
// plaintext leaking into the response envelope.
type Clipboard interface {
	// Write writes plaintext to the clipboard and schedules a best-effort
	// clear after ttl. plaintext bytes are caller-owned — the caller
	// zeroizes them after Write returns.
	Write(plaintext []byte, ttl time.Duration) error
}

// NoopClipboard is the explicit fallback when no OS clipboard backend is
// available. Write always returns ErrUnavailable so the handler surfaces the
// real copy failure.
type NoopClipboard struct{}

func (NoopClipboard) Write(plaintext []byte, ttl time.Duration) error {
	_ = plaintext
	_ = ttl
	return ErrUnavailable
}

// MemoryClipboard is a test fake. Use it in unit tests to assert
// write / last-hash / clear-scheduled lifecycle. plaintext bytes are not
// copied into the fake; only the SHA-256 hash is kept — same spirit as the
// response / logger echo regression guards.
type MemoryClipboard struct {
	mu        sync.Mutex
	writeCnt  int
	lastHash  [32]byte
	hasHash   bool
	lastTTLMs int64
}

func NewMemoryClipboard() *MemoryClipboard { return &MemoryClipboard{} }

func (m *MemoryClipboard) Write(plaintext []byte, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.writeCnt++
	m.lastHash = sha256.Sum256(plaintext)
	m.hasHash = true
	m.lastTTLMs = ttl.Milliseconds()
	return nil
}

// WriteCount returns how many times Write was called.
func (m *MemoryClipboard) WriteCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.writeCnt
}

// LastHash returns the SHA-256 hash from the most recent Write. Zero array
// when hasHash is false.
func (m *MemoryClipboard) LastHash() ([32]byte, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastHash, m.hasHash
}

// LastTTLMs returns the ttl from the most recent Write in ms. Verification
// guard.
func (m *MemoryClipboard) LastTTLMs() int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastTTLMs
}
