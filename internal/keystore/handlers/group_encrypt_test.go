// group_encrypt_test.go — HandleGroupEncryptBound guards (the AAD-free
// HandleGroupEncrypt is refused; see bound_token_test.go).
//
// Core guarantees:
//   1. roundtrip: the sealed {iv, ciphertext} decrypts back to the plaintext
//      under the same raw Group DEK and the bound token AAD.
//   2. response envelope carries plaintext 0 times.
//   3. logger Messages echo the plaintext sentinel 0 times (success path too).
//   4. bad handle → not_found; expired session → expired_session.

package handlers

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"github.com/dragpass/keeper/internal/keystore/crypto"
	"strings"
	"testing"
	"time"

	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

func TestHandleGroupEncryptBound_RoundTrip(t *testing.T) {
	deps, _, _ := newTestDeps(t)
	handle, groupRaw := openSessionForFreshKey(t, deps)

	const plaintextSentinel = "GROUP_ENCRYPT_PLAINTEXT_SENTINEL"
	plaintextB64 := base64.StdEncoding.EncodeToString([]byte(plaintextSentinel))

	resp := HandleGroupEncryptBound(deps, proto.GroupEncryptBoundRequest{
		GroupHandle: handle, OrgID: boundOrg, GroupID: boundGroup, DekVersion: 7, TokenExpiry: "never",
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

	// Decrypt back with the raw Group DEK under the bound token AAD — the
	// group_decrypt_bound_to_clipboard open path.
	aad := proto.BoundGroupTokenAAD(boundOrg, boundGroup, 7, "", proto.TokenExpiry{})
	got, err := crypto.OpenAESGCM(groupRaw, iv, ct, []byte(aad))
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
func TestHandleGroupEncryptBound_NoSecretInLogger(t *testing.T) {
	deps, log, _ := newTestDeps(t)
	handle, groupRaw := openSessionForFreshKey(t, deps)

	const sentinel = "GROUP_ENCRYPT_LOGGER_LEAK_SENTINEL"
	resp := HandleGroupEncryptBound(deps, proto.GroupEncryptBoundRequest{
		GroupHandle: handle, OrgID: boundOrg, GroupID: boundGroup, DekVersion: 7, TokenExpiry: "never",
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
func TestHandleGroupEncryptBound_BadHandle(t *testing.T) {
	deps, _, _ := newTestDeps(t)

	resp := HandleGroupEncryptBound(deps, proto.GroupEncryptBoundRequest{
		GroupHandle: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", OrgID: boundOrg, GroupID: boundGroup,
		DekVersion: 7, TokenExpiry: "never",
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
func TestHandleGroupEncryptBound_ExpiredSession(t *testing.T) {
	deps, _, _ := newTestDeps(t)
	handle, _ := openSessionForFreshKey(t, deps)

	// Jump the clock past the TTL to force expiry.
	deps.GroupSessions.SetClock(func() time.Time { return time.Now().Add(1 * time.Hour) })

	resp := HandleGroupEncryptBound(deps, proto.GroupEncryptBoundRequest{
		GroupHandle: handle, OrgID: boundOrg, GroupID: boundGroup, DekVersion: 7, TokenExpiry: "never",
		PlaintextB64: base64.StdEncoding.EncodeToString([]byte("x")),
	})
	if resp.Success {
		t.Fatalf("expected failure on expired group session")
	}
	if resp.ErrorCode != string(errs.ErrCodeExpiredSession) {
		t.Fatalf("error_code = %q, want %q", resp.ErrorCode, errs.ErrCodeExpiredSession)
	}
}

// The IV comes from Deps.Rand like every other random value a handler draws,
// so a failing source fails the seal instead of falling back to crypto/rand.
func TestHandleGroupEncryptBound_DrawsTheIVFromDepsRand(t *testing.T) {
	deps, _, _ := newTestDeps(t)
	handle, _ := openSessionForFreshKey(t, deps)
	request := proto.GroupEncryptBoundRequest{
		GroupHandle: handle, OrgID: boundOrg, GroupID: boundGroup, DekVersion: 7, TokenExpiry: "never",
		PlaintextB64: base64.StdEncoding.EncodeToString([]byte("x")),
	}

	fixedIV := []byte("twelve-bytes")
	deps.Rand = bytes.NewReader(fixedIV)
	resp := HandleGroupEncryptBound(deps, request)
	if !resp.Success {
		t.Fatalf("seal: %s", resp.Error)
	}
	if got := resp.Data.(proto.GroupEncryptResponseData).IVB64; got != base64.StdEncoding.EncodeToString(fixedIV) {
		t.Fatalf("iv = %s, want the bytes Deps.Rand supplied", got)
	}

	deps.Rand = failingReader{}
	if resp := HandleGroupEncryptBound(deps, request); resp.Success {
		t.Fatal("a failing Deps.Rand must fail the seal")
	}
}
