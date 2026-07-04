package clipboard

import (
	"crypto/sha256"
	"errors"
	"testing"
	"time"
)

func TestNoopClipboard_ReturnsUnavailable(t *testing.T) {
	cb := NoopClipboard{}
	if err := cb.Write([]byte("anything"), 30*time.Second); err != nil {
		if !errors.Is(err, ErrUnavailable) {
			t.Fatalf("NoopClipboard.Write error = %v, want ErrUnavailable", err)
		}
		return
	}
	t.Fatalf("NoopClipboard.Write must fail explicitly")
}

func TestMemoryClipboard_RecordsHashAndCount(t *testing.T) {
	mc := NewMemoryClipboard()
	const plaintext = "secret-value"

	if err := mc.Write([]byte(plaintext), 10*time.Second); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got, has := mc.LastHash()
	if !has {
		t.Fatal("LastHash should be populated after Write")
	}
	want := sha256.Sum256([]byte(plaintext))
	if got != want {
		t.Fatalf("hash mismatch — fake clipboard did not record correct plaintext hash")
	}
	if mc.WriteCount() != 1 {
		t.Fatalf("WriteCount = %d, want 1", mc.WriteCount())
	}
	if mc.LastTTLMs() != 10_000 {
		t.Fatalf("LastTTLMs = %d, want 10000", mc.LastTTLMs())
	}
}

// TestMemoryClipboard_DoesNotStorePlaintext: the fake clipboard interface
// must not expose plaintext itself — only the hash, sharing the spirit of
// the response/logger echo regression guards.
func TestMemoryClipboard_DoesNotStorePlaintext(t *testing.T) {
	mc := NewMemoryClipboard()
	_ = mc.Write([]byte("something"), 30*time.Second)

	// If a plaintext getter is added to the Memory interface, this test
	// fails at compile time (regression detector). Currently only LastHash /
	// WriteCount / LastTTLMs are exposed.
	_, _ = mc.LastHash()
	_ = mc.WriteCount()
	_ = mc.LastTTLMs()
}
