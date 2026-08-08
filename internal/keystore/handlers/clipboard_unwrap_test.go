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

func withMemoryClipboard(t *testing.T) (Deps, *clipboard.MemoryClipboard) {
	t.Helper()
	deps, _, _ := newTestDeps(t)
	mc := clipboard.NewMemoryClipboard()
	deps.Clipboard = mc
	return deps, mc
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

func TestHandleDEKUnwrapAndDecryptToClipboard_RoundTrip(t *testing.T) {
	deps, mc := withMemoryClipboard(t)

	deviceKey := make([]byte, 32)
	if _, err := rand.Read(deviceKey); err != nil {
		t.Fatalf("rand: %v", err)
	}
	if err := saveDeviceKeyForTest(deps, deviceKey); err != nil {
		t.Fatalf("save device key: %v", err)
	}

	signup := HandleDEKGenerateAndWrapDual(deps, proto.DEKGenerateAndWrapDualRequest{Password: "test-pw"})
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

func saveDeviceKeyForTest(deps Deps, key []byte) error {
	return keychain.SaveDeviceKey(deps.Store, base64.StdEncoding.EncodeToString(key))
}
