// production.go — OS clipboard production implementation.
//
// Delegates to `golang.design/x/clipboard`. NSPasteboard on macOS, User32
// OpenClipboard on Windows, X11 selection on Linux X11. All in-process calls,
// so plaintext does not transit child-process stdin/argv.
//
// **Wayland caveat:** the library's Init can fail without an active surface.
// NewProductionClipboard falls back to NoopClipboard on Init failure, but its
// Write returns ErrUnavailable so decrypt-to-clipboard responses are not
// disguised as success.
// See security/keeper-plaintext-command-api-plan.md "Wayland policy".

package clipboard

import (
	"crypto/sha256"
	"sync"
	"time"

	osclip "golang.design/x/clipboard"
)

// NewProductionClipboard tries to Init the OS clipboard library and returns
// an OSClipboard. On Init failure, falls back to NoopClipboard — so the
// dispatcher does not panic on Wayland-like surface-less environments, while
// copy actions fail explicitly.
//
// Guarded by sync.Once so Init runs once per invocation. The library itself
// guarantees idempotence, but an explicit single call is easier for reviewers
// to trace.
func NewProductionClipboard() Clipboard {
	productionInitOnce.Do(func() {
		productionInitErr = osclip.Init()
	})
	if productionInitErr != nil {
		return NoopClipboard{}
	}
	return &OSClipboard{}
}

var (
	productionInitOnce sync.Once
	productionInitErr  error
)

// OSClipboard is the production implementation. SHA-256-hash-based
// compare-then-clear: at TTL expiry, if the user has copied a different value
// in the meantime, do not erase.
//
// When concurrent Writes arrive, the most recent one wins (lastHash is
// updated). The previous clear schedule is then re-compared against the new
// hash and remains meaningful — since the old value can no longer be on the
// clipboard, it becomes a no-op automatically.
type OSClipboard struct {
	mu       sync.Mutex
	lastHash [32]byte
	hasHash  bool
}

// Write writes plaintext to the OS clipboard and schedules a best-effort
// clear after ttl. plaintext bytes are caller-owned — the caller zeroizes
// them immediately after Write returns.
//
// **String-conversion carve-out:** golang.design/x/clipboard.Write takes
// []byte, so this call does not convert plaintext to a string. Whether the
// Go runtime creates a temporary copy on the GC heap is not guaranteed
// (see non-goals).
func (c *OSClipboard) Write(plaintext []byte, ttl time.Duration) error {
	hash := sha256.Sum256(plaintext)

	c.mu.Lock()
	c.lastHash = hash
	c.hasHash = true
	c.mu.Unlock()

	osclip.Write(osclip.FmtText, plaintext)

	go c.scheduleClear(hash, ttl)
	return nil
}

// scheduleClear reads the clipboard after ttl and clears only when the hash
// matches. If the user copied a different value in the meantime, the hash
// mismatches and this is a no-op — best-effort protection.
func (c *OSClipboard) scheduleClear(expected [32]byte, ttl time.Duration) {
	timer := time.NewTimer(ttl)
	defer timer.Stop()
	<-timer.C

	current := osclip.Read(osclip.FmtText)
	if len(current) == 0 {
		return // already empty
	}
	got := sha256.Sum256(current)
	if got != expected {
		return // user copied a different value — protect
	}
	osclip.Write(osclip.FmtText, []byte{})
}
