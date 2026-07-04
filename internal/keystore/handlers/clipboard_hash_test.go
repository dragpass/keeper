// clipboard_hash_test.go — HandleClipboardGetLastHash 가드.
package handlers

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/clipboard"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

func TestHandleClipboardGetLastHash_NoWrite(t *testing.T) {
	deps, _ := withMemoryClipboard(t)

	resp := HandleClipboardGetLastHash(deps, proto.ClipboardGetLastHashRequest{})
	if !resp.Success {
		t.Fatalf("expected success: %v", resp.Error)
	}
	d := resp.Data.(proto.ClipboardGetLastHashResponseData)
	if d.HasHash {
		t.Fatalf("HasHash should be false on fresh clipboard")
	}
	if d.WriteCount != 0 {
		t.Fatalf("WriteCount=%d, want 0", d.WriteCount)
	}
	// Even with an empty hash, LastHashB64 is base64 of 32 zero bytes — length is fixed.
	if got := len(d.LastHashB64); got == 0 {
		t.Fatalf("LastHashB64 should be base64(32 zero bytes), got empty")
	}
}

// TestHandleClipboardGetLastHash_RecordsHashOfPlaintext — after a
// clipboard.Write call, hash must match SHA-256(plaintext) and
// WriteCount/LastTTLMs are correct.
// This guard is core to dispatch-path validation in E2E tests.
func TestHandleClipboardGetLastHash_RecordsHashOfPlaintext(t *testing.T) {
	deps, mc := withMemoryClipboard(t)

	// Call Clipboard.Write directly — bypass the handler, only trigger hash recording.
	const plaintext = "PLAINTEXT_HASH_PROBE"
	if err := mc.Write([]byte(plaintext), 30_000_000_000); err != nil { // 30s in ns
		t.Fatalf("Write: %v", err)
	}

	resp := HandleClipboardGetLastHash(deps, proto.ClipboardGetLastHashRequest{})
	if !resp.Success {
		t.Fatalf("expected success: %v", resp.Error)
	}
	d := resp.Data.(proto.ClipboardGetLastHashResponseData)
	if !d.HasHash {
		t.Fatalf("HasHash should be true after Write")
	}
	if d.WriteCount != 1 {
		t.Fatalf("WriteCount=%d, want 1", d.WriteCount)
	}

	expected := sha256.Sum256([]byte(plaintext))
	want := base64.StdEncoding.EncodeToString(expected[:])
	if d.LastHashB64 != want {
		t.Fatalf("LastHashB64 mismatch:\n got=%s\nwant=%s", d.LastHashB64, want)
	}

	// Response envelope itself must not echo plaintext — regression guard.
	raw, _ := json.Marshal(resp)
	if strings.Contains(string(raw), plaintext) {
		t.Fatalf("response leaked plaintext: %s", string(raw))
	}
}

// TestHandleClipboardGetLastHash_ProductionClipboardRejected — when a
// Clipboard impl that fails the type assertion (like the production
// OSClipboard) is injected, the action must be rejected with
// ErrCodeUnsupported. Guarantees structural safety even if it is invoked
// outside KEEPER_E2E_MODE.
func TestHandleClipboardGetLastHash_ProductionClipboardRejected(t *testing.T) {
	deps, _, _ := newTestDeps(t)
	// NoopClipboard instead of MemoryClipboard — fails type assertion like
	// the production OSClipboard.
	deps.Clipboard = clipboard.NoopClipboard{}

	resp := HandleClipboardGetLastHash(deps, proto.ClipboardGetLastHashRequest{})
	if resp.Success {
		t.Fatalf("expected failure for non-MemoryClipboard")
	}
	if !strings.Contains(resp.Error, "MemoryClipboard") {
		t.Fatalf("error should mention MemoryClipboard requirement, got: %s", resp.Error)
	}
}
