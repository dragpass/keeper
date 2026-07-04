// clipboard_group_test.go — HandleGroupDecryptToClipboard 가드.
//
// Core guarantees (clipboard_unwrap_test 와 동일):
//   1. response envelope plaintext-free
//   2. logger plaintext-free
//   3. clipboard_ttl_ms range validation
//   4. d.Clipboard.Write 정확히 1회 호출 + SHA-256 hash 일치
//   5. plaintext slice 즉시 zeroize

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

func TestHandleGroupDecryptToClipboard_RoundTrip(t *testing.T) {
	deps, mc := withMemoryClipboard(t)
	handle, groupRaw := openSessionForFreshKey(t, deps)

	const plaintextSentinel = "GROUP_PLAINTEXT_SENTINEL"

	// Prelude: like the Extension, AES-GCM seal directly with raw Group DEK.
	// Split IV / ciphertext with AESGCMSealSplit.
	iv, ct, err := AESGCMSealSplit(groupRaw, []byte(plaintextSentinel))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	resp := HandleGroupDecryptToClipboard(deps, proto.GroupDecryptToClipboardRequest{
		GroupHandle:    handle,
		IVB64:          base64.StdEncoding.EncodeToString(iv),
		CiphertextB64:  base64.StdEncoding.EncodeToString(ct),
		ClipboardTTLMs: 30_000,
	})
	if !resp.Success {
		t.Fatalf("expected success, got error: %s", resp.Error)
	}
	data, ok := resp.Data.(proto.ClipboardCopyResponseData)
	if !ok {
		t.Fatalf("response data type = %T, want ClipboardCopyResponseData", resp.Data)
	}
	if !data.Copied || data.ClipboardTTLMs != 30_000 {
		t.Fatalf("response = %+v, want {Copied:true, TTL:30000}", data)
	}

	got, has := mc.LastHash()
	if !has {
		t.Fatalf("Clipboard.Write was not called")
	}
	want := sha256.Sum256([]byte(plaintextSentinel))
	if got != want {
		t.Fatalf("clipboard hash mismatch — plaintext did not reach Clipboard intact")
	}
	if mc.WriteCount() != 1 {
		t.Fatalf("Clipboard.Write called %d times, want 1", mc.WriteCount())
	}

	respJSON, _ := json.Marshal(resp)
	for _, banned := range []string{"plaintext_b64", "plaintext", plaintextSentinel} {
		if strings.Contains(string(respJSON), banned) {
			t.Fatalf("response leaked %q: %s", banned, respJSON)
		}
	}
}

// TestHandleGroupDecryptToClipboard_RejectsInvalidTTL — clipboard_ttl_ms
// range validation.
func TestHandleGroupDecryptToClipboard_RejectsInvalidTTL(t *testing.T) {
	deps, mc := withMemoryClipboard(t)
	handle, _ := openSessionForFreshKey(t, deps)

	cases := []int64{0, 4_999, 60_001}
	for _, ttl := range cases {
		resp := HandleGroupDecryptToClipboard(deps, proto.GroupDecryptToClipboardRequest{
			GroupHandle:    handle,
			IVB64:          base64.StdEncoding.EncodeToString(make([]byte, 12)),
			CiphertextB64:  "AAAA",
			ClipboardTTLMs: ttl,
		})
		if resp.Success {
			t.Fatalf("ttl %d should be rejected", ttl)
		}
		if !strings.Contains(resp.Error, "clipboard_ttl_ms") {
			t.Fatalf("ttl %d error must mention clipboard_ttl_ms, got %q", ttl, resp.Error)
		}
	}
	if mc.WriteCount() != 0 {
		t.Fatalf("Clipboard.Write must not be called on validation failure")
	}
}

// TestHandleGroupDecryptToClipboard_BadHandle — an unregistered group_handle
// is rejected and clipboard.Write is not called.
func TestHandleGroupDecryptToClipboard_BadHandle(t *testing.T) {
	deps, mc := withMemoryClipboard(t)

	resp := HandleGroupDecryptToClipboard(deps, proto.GroupDecryptToClipboardRequest{
		GroupHandle:    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		IVB64:          base64.StdEncoding.EncodeToString(make([]byte, 12)),
		CiphertextB64:  "AAAA",
		ClipboardTTLMs: 30_000,
	})
	if resp.Success {
		t.Fatalf("expected failure on missing group session")
	}
	if mc.WriteCount() != 0 {
		t.Fatalf("Clipboard.Write must not run on session miss")
	}
}

// TestHandleGroupDecryptToClipboard_NoPlaintextInLogger — the plaintext
// sentinel must not echo into the logger Messages.
func TestHandleGroupDecryptToClipboard_NoPlaintextInLogger(t *testing.T) {
	deps, log, _ := newTestDeps(t)
	deps.Clipboard = clipboard.NewMemoryClipboard()
	handle, groupRaw := openSessionForFreshKey(t, deps)

	const sentinel = "GROUP_LOGGER_LEAK_SENTINEL"
	iv, ct, err := AESGCMSealSplit(groupRaw, []byte(sentinel))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	HandleGroupDecryptToClipboard(deps, proto.GroupDecryptToClipboardRequest{
		GroupHandle:    handle,
		IVB64:          base64.StdEncoding.EncodeToString(iv),
		CiphertextB64:  base64.StdEncoding.EncodeToString(ct),
		ClipboardTTLMs: 30_000,
	})

	if log.Contains(sentinel) {
		t.Fatalf("logger leaked plaintext sentinel: %v", log.Messages())
	}
}
