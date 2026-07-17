// group_encrypt_aad_test.go — HandleGroupEncryptWithAAD guards.
//
// Core guarantees:
//   1. AAD roundtrip: the sealed {iv, ciphertext} decrypts back to the
//      plaintext under the same raw Group DEK AND the same AAD.
//   2. swap negative: opening with a DIFFERENT AAD fails (this is the whole
//      point of the action — a ciphertext cannot be swapped to another context).
//   3. response envelope + logger carry plaintext 0 times (success path too).
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

func TestHandleGroupEncryptWithAAD_RoundTrip(t *testing.T) {
	deps, _, _ := newTestDeps(t)
	handle, groupRaw := openSessionForFreshKey(t, deps)

	const plaintextSentinel = "GROUP_ENCRYPT_AAD_PLAINTEXT_SENTINEL"
	plaintextB64 := base64.StdEncoding.EncodeToString([]byte(plaintextSentinel))
	// Canonical AAD: org_id|entry_id|payload_kind|schema_version|dek_version.
	aad := []byte("org_42|entry_7|credential|1|3")
	aadB64 := base64.StdEncoding.EncodeToString(aad)

	resp := HandleGroupEncryptWithAAD(deps, proto.GroupEncryptWithAADRequest{
		GroupHandle:  handle,
		PlaintextB64: plaintextB64,
		AADB64:       aadB64,
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

	// Opening with the SAME AAD succeeds and yields the plaintext.
	got, err := AESGCMOpenWithAAD(groupRaw, iv, ct, aad)
	if err != nil {
		t.Fatalf("open with matching AAD: %v", err)
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

// TestHandleGroupEncryptWithAAD_SwapAADFails — the swap-prevention guarantee.
// A ciphertext sealed under one canonical AAD must NOT open under a different
// AAD (a swapped org_id / entry_id / payload_kind / version), even with the
// correct raw Group DEK.
func TestHandleGroupEncryptWithAAD_SwapAADFails(t *testing.T) {
	deps, _, _ := newTestDeps(t)
	handle, groupRaw := openSessionForFreshKey(t, deps)

	plaintextB64 := base64.StdEncoding.EncodeToString([]byte("secret payload"))
	sealAAD := []byte("org_42|entry_7|credential|1|3")
	// Attacker swaps the entry_id — a different context for the same key.
	swappedAAD := []byte("org_42|entry_9|credential|1|3")

	resp := HandleGroupEncryptWithAAD(deps, proto.GroupEncryptWithAADRequest{
		GroupHandle:  handle,
		PlaintextB64: plaintextB64,
		AADB64:       base64.StdEncoding.EncodeToString(sealAAD),
	})
	if !resp.Success {
		t.Fatalf("expected success, got error: %s", resp.Error)
	}
	data := resp.Data.(proto.GroupEncryptResponseData)
	iv, _ := base64.StdEncoding.DecodeString(data.IVB64)
	ct, _ := base64.StdEncoding.DecodeString(data.CiphertextB64)

	// Opening with the swapped AAD must fail (GCM tag mismatch).
	if _, err := AESGCMOpenWithAAD(groupRaw, iv, ct, swappedAAD); err == nil {
		t.Fatalf("open with swapped AAD unexpectedly succeeded — swap guard broken")
	}
	// Opening with an empty/nil AAD (as plain group_encrypt would) must also fail.
	if _, err := AESGCMOpen(groupRaw, iv, ct); err == nil {
		t.Fatalf("open with nil AAD unexpectedly succeeded — AAD not bound into tag")
	}
	// Sanity: the correct AAD still opens.
	if _, err := AESGCMOpenWithAAD(groupRaw, iv, ct, sealAAD); err != nil {
		t.Fatalf("open with matching AAD failed: %v", err)
	}
}

// TestHandleGroupEncryptWithAAD_NoSecretInLogger — the plaintext sentinel and
// the raw Group DEK must not echo into the logger Messages on the success path.
func TestHandleGroupEncryptWithAAD_NoSecretInLogger(t *testing.T) {
	deps, log, _ := newTestDeps(t)
	handle, groupRaw := openSessionForFreshKey(t, deps)

	const sentinel = "GROUP_ENCRYPT_AAD_LOGGER_LEAK_SENTINEL"
	resp := HandleGroupEncryptWithAAD(deps, proto.GroupEncryptWithAADRequest{
		GroupHandle:  handle,
		PlaintextB64: base64.StdEncoding.EncodeToString([]byte(sentinel)),
		AADB64:       base64.StdEncoding.EncodeToString([]byte("org_1|entry_1|credential|1|1")),
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

// TestHandleGroupEncryptWithAAD_BadHandle — an unregistered group_handle is
// rejected with not_found.
func TestHandleGroupEncryptWithAAD_BadHandle(t *testing.T) {
	deps, _, _ := newTestDeps(t)

	resp := HandleGroupEncryptWithAAD(deps, proto.GroupEncryptWithAADRequest{
		GroupHandle:  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		PlaintextB64: base64.StdEncoding.EncodeToString([]byte("x")),
		AADB64:       base64.StdEncoding.EncodeToString([]byte("org_1|entry_1|credential|1|1")),
	})
	if resp.Success {
		t.Fatalf("expected failure on missing group session")
	}
	if resp.ErrorCode != string(errs.ErrCodeNotFound) {
		t.Fatalf("error_code = %q, want %q", resp.ErrorCode, errs.ErrCodeNotFound)
	}
}

// TestHandleGroupEncryptWithAAD_ExpiredSession — an expired handle is rejected
// with expired_session.
func TestHandleGroupEncryptWithAAD_ExpiredSession(t *testing.T) {
	deps, _, _ := newTestDeps(t)
	handle, _ := openSessionForFreshKey(t, deps)

	// Jump the clock past the TTL to force expiry.
	deps.GroupSessions.SetClock(func() time.Time { return time.Now().Add(1 * time.Hour) })

	resp := HandleGroupEncryptWithAAD(deps, proto.GroupEncryptWithAADRequest{
		GroupHandle:  handle,
		PlaintextB64: base64.StdEncoding.EncodeToString([]byte("x")),
		AADB64:       base64.StdEncoding.EncodeToString([]byte("org_1|entry_1|credential|1|1")),
	})
	if resp.Success {
		t.Fatalf("expected failure on expired group session")
	}
	if resp.ErrorCode != string(errs.ErrCodeExpiredSession) {
		t.Fatalf("error_code = %q, want %q", resp.ErrorCode, errs.ErrCodeExpiredSession)
	}
}
