// group_encrypt_test.go — HandleGroupEncrypt guards.
//
// Core guarantees:
//   1. roundtrip: the sealed {iv, ciphertext} decrypts back to the plaintext
//      under the same raw Group DEK (aesGCMOpen).
//   2. response envelope carries plaintext 0 times.
//   3. logger Messages echo the plaintext sentinel 0 times (success path too).
//   4. bad handle → not_found; expired session → expired_session.

package handlers

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

func TestHandleGroupEncrypt_RoundTrip(t *testing.T) {
	deps, _, _ := newTestDeps(t)
	handle, groupRaw := openSessionForFreshKey(t, deps)

	const plaintextSentinel = "GROUP_ENCRYPT_PLAINTEXT_SENTINEL"
	plaintextB64 := base64.StdEncoding.EncodeToString([]byte(plaintextSentinel))

	resp := HandleGroupEncrypt(deps, proto.GroupEncryptRequest{
		GroupHandle:  handle,
		PlaintextB64: plaintextB64,
	})
	if !resp.Success {
		t.Fatalf("expected success, got error: %s", resp.Error)
	}
	data, ok := resp.Data.(proto.GroupEncryptResponseData)
	if !ok {
		t.Fatalf("response data type = %T, want GroupEncryptResponseData", resp.Data)
	}

	iv, err := base64.StdEncoding.DecodeString(data.IVB64)
	if err != nil {
		t.Fatalf("decode iv: %v", err)
	}
	ct, err := base64.StdEncoding.DecodeString(data.CiphertextB64)
	if err != nil {
		t.Fatalf("decode ciphertext: %v", err)
	}

	// Decrypt back directly with the raw Group DEK — mirror of the client-side
	// / group_decrypt_to_clipboard open path.
	got, err := AESGCMOpen(groupRaw, iv, ct)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if string(got) != plaintextSentinel {
		t.Fatalf("roundtrip plaintext mismatch: got %q, want %q", got, plaintextSentinel)
	}

	// Response JSON must contain plaintext / plaintext_b64 / sentinel 0 times.
	respJSON, _ := json.Marshal(resp)
	for _, banned := range []string{"plaintext_b64", "plaintext", plaintextSentinel, plaintextB64} {
		if strings.Contains(string(respJSON), banned) {
			t.Fatalf("response leaked %q: %s", banned, respJSON)
		}
	}
}

// TestHandleGroupEncrypt_NoSecretInLogger — the plaintext sentinel and the raw
// Group DEK must not echo into the logger Messages on the success path.
func TestHandleGroupEncrypt_NoSecretInLogger(t *testing.T) {
	deps, log, _ := newTestDeps(t)
	handle, groupRaw := openSessionForFreshKey(t, deps)

	const sentinel = "GROUP_ENCRYPT_LOGGER_LEAK_SENTINEL"
	resp := HandleGroupEncrypt(deps, proto.GroupEncryptRequest{
		GroupHandle:  handle,
		PlaintextB64: base64.StdEncoding.EncodeToString([]byte(sentinel)),
	})
	if !resp.Success {
		t.Fatalf("expected success, got error: %s", resp.Error)
	}

	if log.Contains(sentinel) {
		t.Fatalf("logger leaked plaintext sentinel: %v", log.Messages())
	}
	rawDEKB64 := base64.StdEncoding.EncodeToString(groupRaw)
	if log.Contains(rawDEKB64) {
		t.Fatalf("logger leaked raw Group DEK: %v", log.Messages())
	}
}

// TestHandleGroupEncrypt_BadHandle — an unregistered group_handle is rejected
// with not_found.
func TestHandleGroupEncrypt_BadHandle(t *testing.T) {
	deps, _, _ := newTestDeps(t)

	resp := HandleGroupEncrypt(deps, proto.GroupEncryptRequest{
		GroupHandle:  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		PlaintextB64: base64.StdEncoding.EncodeToString([]byte("x")),
	})
	if resp.Success {
		t.Fatalf("expected failure on missing group session")
	}
	if resp.ErrorCode != string(errs.ErrCodeNotFound) {
		t.Fatalf("error_code = %q, want %q", resp.ErrorCode, errs.ErrCodeNotFound)
	}
}

// TestHandleGroupEncrypt_ExpiredSession — an expired handle is rejected with
// expired_session.
func TestHandleGroupEncrypt_ExpiredSession(t *testing.T) {
	deps, _, _ := newTestDeps(t)
	handle, _ := openSessionForFreshKey(t, deps)

	// Jump the clock past the TTL to force expiry.
	deps.GroupSessions.SetClock(func() time.Time { return time.Now().Add(1 * time.Hour) })

	resp := HandleGroupEncrypt(deps, proto.GroupEncryptRequest{
		GroupHandle:  handle,
		PlaintextB64: base64.StdEncoding.EncodeToString([]byte("x")),
	})
	if resp.Success {
		t.Fatalf("expected failure on expired group session")
	}
	if resp.ErrorCode != string(errs.ErrCodeExpiredSession) {
		t.Fatalf("error_code = %q, want %q", resp.ErrorCode, errs.ErrCodeExpiredSession)
	}
}
