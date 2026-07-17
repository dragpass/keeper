// clipboard_unwrap_test.go — AES / DEK unwrap-and-decrypt-to-clipboard 핸들러
// + finalizeClipboardCopy 가드.
//
// Core guarantees:
//   1. response envelope contains plaintext / plaintext_b64 / preview / length metadata 0 times
//   2. logger Messages echo plaintext sentinel 0 times
//   3. clipboard_ttl_ms range validation (5_000 ~ 60_000)
//   4. d.Clipboard.Write is called exactly once and the SHA-256 hash matches plaintext
//   5. plaintext slice is zeroized immediately after handler call

package handlers

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/clipboard"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// withMemoryClipboard wires a MemoryClipboard into newTestDeps.
// 본 helper 는 clipboard_*_test.go 모든 분할 파일이 공유한다.
func withMemoryClipboard(t *testing.T) (Deps, *clipboard.MemoryClipboard) {
	t.Helper()
	deps, _, _ := newTestDeps(t)
	mc := clipboard.NewMemoryClipboard()
	deps.Clipboard = mc
	return deps, mc
}

// TestHandleAESUnwrapAndDecryptToClipboard_RoundTrip — the exact plaintext
// reaches the fake clipboard and the response carries plaintext 0 times.
func TestHandleAESUnwrapAndDecryptToClipboard_RoundTrip(t *testing.T) {
	deps, mc := withMemoryClipboard(t)
	handle, raw := openSessionForFreshKey(t, deps)

	// plaintext uses a sentinel — shared with other regression guards (logger / response echo).
	const plaintextSentinel = "PLAINTEXT_SENTINEL_DO_NOT_LEAK"
	plaintextB64 := base64.StdEncoding.EncodeToString([]byte(plaintextSentinel))

	// Prelude: wrap a fresh Item DEK + encrypt to produce wrapped + iv + ct.
	wrapped, _ := wrapFreshItemDEK(t, raw)
	enc := HandleAESUnwrapAndEncrypt(deps, proto.AESUnwrapAndEncryptRequest{
		WrappedItemDEK: wrapped,
		GroupHandle:    handle,
		PlaintextB64:   plaintextB64,
	})
	encData := enc.Data.(proto.AESUnwrapAndEncryptResponseData)

	resp := HandleAESUnwrapAndDecryptToClipboard(deps, proto.AESUnwrapAndDecryptToClipboardRequest{
		WrappedItemDEK: wrapped,
		GroupHandle:    handle,
		IVB64:          encData.IVB64,
		CiphertextB64:  encData.CiphertextB64,
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

	// fake clipboard hash must match the sentinel's SHA-256.
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

	// Response JSON must contain plaintext_b64 / plaintext / sentinel 0 times.
	respJSON, _ := json.Marshal(resp)
	for _, banned := range []string{"plaintext_b64", "plaintext", plaintextSentinel, plaintextB64} {
		if strings.Contains(string(respJSON), banned) {
			t.Fatalf("response leaked %q: %s", banned, respJSON)
		}
	}
}

func TestFinalizeClipboardCopy_UnavailableClipboardFails(t *testing.T) {
	deps, _ := withMemoryClipboard(t)
	deps.Clipboard = clipboard.NoopClipboard{}

	plaintext := []byte("clipboard-unavailable-sentinel")
	resp := finalizeClipboardCopy(deps, plaintext, 30_000, "test copy")
	if resp.Success {
		t.Fatalf("copy must fail when clipboard backend is unavailable")
	}
	if !strings.Contains(resp.Error, "clipboard unavailable") {
		t.Fatalf("error should mention unavailable clipboard, got: %s", resp.Error)
	}
	for i, b := range plaintext {
		if b != 0 {
			t.Fatalf("plaintext byte %d not zeroized after copy failure", i)
		}
	}
}

// TestHandleDEKUnwrapAndDecryptToClipboard_RoundTrip — same guarantees on the
// personal DEK path.
func TestHandleDEKUnwrapAndDecryptToClipboard_RoundTrip(t *testing.T) {
	deps, mc := withMemoryClipboard(t)

	// device key seed.
	deviceKey := make([]byte, 32)
	if _, err := rand.Read(deviceKey); err != nil {
		t.Fatalf("rand: %v", err)
	}
	if err := saveDeviceKeyForTest(deps, deviceKey); err != nil {
		t.Fatalf("save device key: %v", err)
	}

	// signup → encrypt prelude. Issue device-wrapped DEK via dual wrap.
	signup := HandleDEKGenerateAndWrapDual(deps, proto.DEKGenerateAndWrapDualRequest{
		Password: "test-pw",
	})
	if !signup.Success {
		t.Fatalf("signup setup: %s", signup.Error)
	}
	dual := signup.Data.(proto.DEKGenerateAndWrapDualResponseData)

	const plaintextSentinel = "DEK_PLAINTEXT_SENTINEL"
	enc := HandleDEKUnwrapAndEncrypt(deps, proto.DEKUnwrapAndEncryptRequest{
		EncryptedDEKB64: dual.DeviceWrappedDEKB64,
		PlaintextB64:    base64.StdEncoding.EncodeToString([]byte(plaintextSentinel)),
	})
	if !enc.Success {
		t.Fatalf("encrypt setup: %s", enc.Error)
	}
	encData := enc.Data.(proto.DEKUnwrapAndEncryptResponseData)

	resp := HandleDEKUnwrapAndDecryptToClipboard(deps, proto.DEKUnwrapAndDecryptToClipboardRequest{
		EncryptedDEKB64: dual.DeviceWrappedDEKB64,
		IVB64:           encData.IVB64,
		CiphertextB64:   encData.CiphertextB64,
		ClipboardTTLMs:  10_000,
	})
	if !resp.Success {
		t.Fatalf("expected success: %s", resp.Error)
	}

	got, has := mc.LastHash()
	if !has {
		t.Fatalf("Clipboard.Write was not called")
	}
	want := sha256.Sum256([]byte(plaintextSentinel))
	if got != want {
		t.Fatalf("clipboard hash mismatch")
	}

	respJSON, _ := json.Marshal(resp)
	for _, banned := range []string{"plaintext_b64", plaintextSentinel} {
		if strings.Contains(string(respJSON), banned) {
			t.Fatalf("response leaked %q: %s", banned, respJSON)
		}
	}
}

// TestHandleAESUnwrapAndDecryptToClipboard_RejectsInvalidTTL — outside the
// 5s/60s range, Validate must reject.
func TestHandleAESUnwrapAndDecryptToClipboard_RejectsInvalidTTL(t *testing.T) {
	deps, mc := withMemoryClipboard(t)
	handle, _ := openSessionForFreshKey(t, deps)

	cases := []int64{0, 1, 4_999, 60_001, 86_400_000}
	for _, ttl := range cases {
		resp := HandleAESUnwrapAndDecryptToClipboard(deps, proto.AESUnwrapAndDecryptToClipboardRequest{
			WrappedItemDEK: "AAAA",
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

// TestHandleAESUnwrapAndDecryptToClipboard_NoPlaintextInLogger — the
// plaintext sentinel must not echo into the logger Messages.
func TestHandleAESUnwrapAndDecryptToClipboard_NoPlaintextInLogger(t *testing.T) {
	deps, log, _ := newTestDeps(t)
	deps.Clipboard = clipboard.NewMemoryClipboard()
	handle, raw := openSessionForFreshKey(t, deps)

	const sentinel = "LOGGER_LEAK_SENTINEL"
	wrapped, _ := wrapFreshItemDEK(t, raw)
	enc := HandleAESUnwrapAndEncrypt(deps, proto.AESUnwrapAndEncryptRequest{
		WrappedItemDEK: wrapped,
		GroupHandle:    handle,
		PlaintextB64:   base64.StdEncoding.EncodeToString([]byte(sentinel)),
	})
	encData := enc.Data.(proto.AESUnwrapAndEncryptResponseData)

	HandleAESUnwrapAndDecryptToClipboard(deps, proto.AESUnwrapAndDecryptToClipboardRequest{
		WrappedItemDEK: wrapped,
		GroupHandle:    handle,
		IVB64:          encData.IVB64,
		CiphertextB64:  encData.CiphertextB64,
		ClipboardTTLMs: 30_000,
	})

	if log.Contains(sentinel) {
		t.Fatalf("logger leaked plaintext sentinel: %v", log.Messages())
	}
}

// TestHandleAESUnwrapAndDecryptToClipboard_BadHandle — a handle with no
// Group session must fail with ErrCodeNotFound and clipboard.Write must not be called.
func TestHandleAESUnwrapAndDecryptToClipboard_BadHandle(t *testing.T) {
	deps, mc := withMemoryClipboard(t)

	resp := HandleAESUnwrapAndDecryptToClipboard(deps, proto.AESUnwrapAndDecryptToClipboardRequest{
		WrappedItemDEK: "AAAA",
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

// saveDeviceKeyForTest seeds the device key directly into newTestDeps's
// MemorySecretStore via keychain.SaveDeviceKey (same pattern as dek_test).
func saveDeviceKeyForTest(deps Deps, key []byte) error {
	return keychain.SaveDeviceKey(deps.Store, base64.StdEncoding.EncodeToString(key))
}
