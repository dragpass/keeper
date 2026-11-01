// Tests for HandleGroupDecryptBoundToClipboard (the AAD-free
// HandleGroupDecryptToClipboard is refused; see bound_token_test.go).
//
// Core guarantees:
//   1. response envelope plaintext-free
//   2. logger plaintext-free
//   3. clipboard_ttl_ms range validation
//   4. d.Clipboard.Write is called exactly once and returns the expected SHA-256 hash
//   5. plaintext is zeroized immediately

package handlers

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"github.com/dragpass/keeper/internal/keystore/crypto"
	"strings"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/clipboard"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

func TestHandleGroupDecryptBoundToClipboard_RoundTrip(t *testing.T) {
	deps, mc := withMemoryClipboard(t)
	handle, groupRaw := openSessionForFreshKey(t, deps)

	const plaintextSentinel = "GROUP_PLAINTEXT_SENTINEL"

	// Prelude: seal under the raw Group DEK with the bound token AAD, as
	// group_encrypt_bound does.
	iv, ct, err := crypto.SealAESGCM(rand.Reader, groupRaw, []byte(plaintextSentinel), boundTestAAD())
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	resp := HandleGroupDecryptBoundToClipboard(deps, proto.GroupDecryptBoundToClipboardRequest{
		GroupHandle: handle, OrgID: boundOrg, GroupID: boundGroup, DekVersion: 7, TokenExpiry: "never",
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
func TestHandleGroupDecryptBoundToClipboard_RejectsInvalidTTL(t *testing.T) {
	deps, mc := withMemoryClipboard(t)
	handle, _ := openSessionForFreshKey(t, deps)

	cases := []int64{0, 4_999, 60_001}
	for _, ttl := range cases {
		resp := HandleGroupDecryptBoundToClipboard(deps, proto.GroupDecryptBoundToClipboardRequest{
			GroupHandle: handle, OrgID: boundOrg, GroupID: boundGroup, DekVersion: 7, TokenExpiry: "never",
			IVB64:          base64.StdEncoding.EncodeToString(make([]byte, 12)),
			CiphertextB64:  base64.StdEncoding.EncodeToString(make([]byte, 16)),
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
func TestHandleGroupDecryptBoundToClipboard_BadHandle(t *testing.T) {
	deps, mc := withMemoryClipboard(t)

	resp := HandleGroupDecryptBoundToClipboard(deps, proto.GroupDecryptBoundToClipboardRequest{
		OrgID: boundOrg, GroupID: boundGroup, DekVersion: 7, TokenExpiry: "never",
		GroupHandle:    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		IVB64:          base64.StdEncoding.EncodeToString(make([]byte, 12)),
		CiphertextB64:  base64.StdEncoding.EncodeToString(make([]byte, 16)),
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
func TestHandleGroupDecryptBoundToClipboard_NoPlaintextInLogger(t *testing.T) {
	deps, log, _ := newTestDeps(t)
	deps.Clipboard = clipboard.NewMemoryClipboard()
	handle, groupRaw := openSessionForFreshKey(t, deps)

	const sentinel = "GROUP_LOGGER_LEAK_SENTINEL"
	iv, ct, err := crypto.SealAESGCM(rand.Reader, groupRaw, []byte(sentinel), boundTestAAD())
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	HandleGroupDecryptBoundToClipboard(deps, proto.GroupDecryptBoundToClipboardRequest{
		GroupHandle: handle, OrgID: boundOrg, GroupID: boundGroup, DekVersion: 7, TokenExpiry: "never",
		IVB64:          base64.StdEncoding.EncodeToString(iv),
		CiphertextB64:  base64.StdEncoding.EncodeToString(ct),
		ClipboardTTLMs: 30_000,
	})

	if log.Contains(sentinel) {
		t.Fatalf("logger leaked plaintext sentinel: %v", log.Messages())
	}
}

func boundTestAAD() []byte {
	return []byte(proto.BoundGroupTokenAAD(boundOrg, boundGroup, 7, "", proto.TokenExpiry{}))
}
