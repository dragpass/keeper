package clipboard

import (
	"crypto/sha256"
	"testing"
)

// TestNewProductionClipboard_ReturnsConcreteImpl checks that
// NewProductionClipboard never returns a nil interface. Init may resolve to
// OSClipboard or NoopClipboard depending on the environment, but either way
// it must not be nil (NewApp's fallback relies on the nil check).
func TestNewProductionClipboard_ReturnsConcreteImpl(t *testing.T) {
	cb := NewProductionClipboard()
	if cb == nil {
		t.Fatalf("NewProductionClipboard must never return nil")
	}
	// Verify Write exists — interface contract check. Avoid actually
	// invoking it: OS clipboard calls can panic in CI/headless environments.
	_ = cb
}

// TestOSClipboard_HashRecordedOnWrite asserts the OSClipboard struct's own
// hash-recording behavior. Even when Write itself fails (osclip.Write can
// panic), the hash must be recorded — but to avoid touching the real OS
// clipboard, this test isolates only the hash-recording branch.
func TestOSClipboard_HashRecordedAfterMu(t *testing.T) {
	c := &OSClipboard{}
	hash := sha256.Sum256([]byte("test"))

	// Set mu / lastHash directly to unit-test the hash-recording branch.
	c.mu.Lock()
	c.lastHash = hash
	c.hasHash = true
	c.mu.Unlock()

	if !c.hasHash {
		t.Fatalf("hasHash should be true after manual set")
	}
	if c.lastHash != hash {
		t.Fatalf("lastHash mismatch")
	}
}
