// guest_transcrypt_test.go — HandleGroupTranscryptForGuest guards.
//
// Core guarantees:
//   1. round-trip: handler output decrypts via the guest-viewer algorithm
//      (K-only and passphrase paths), proving byte-compatibility with
//      dragpass/app/src/shared/lib/guest-share-crypto.ts.
//   2. wire-format constants: IV 12B, guest_key = Base64URL(32B), ciphertext =
//      standard Base64(IV‖ct).
//   3. fixed known-answer vector (documented for frontend e2e cross-check).
//   4. plaintext / Group DEK never appear in response or logger.
//   5. invalid input rejected (passphrase/salt mismatch, bad IV, bad handle).

package handlers

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/proto"
)

// guestViewerDecrypt independently reproduces decryptFromGuest /
// deriveAesKey from guest-share-crypto.ts so the round-trip test is a genuine
// cross-check rather than calling the handler's own derivation. saltB64 empty
// (and passphrase empty) selects the K-only path.
func guestViewerDecrypt(t *testing.T, ciphertextB64, keyB64url, passphrase, saltB64 string) []byte {
	t.Helper()

	payload, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		t.Fatalf("guest_ciphertext not standard Base64: %v", err)
	}
	if len(payload) < 12+16 {
		t.Fatalf("payload too short: %d bytes", len(payload))
	}
	iv, ct := payload[:12], payload[12:]

	k, err := base64.RawURLEncoding.DecodeString(keyB64url)
	if err != nil {
		t.Fatalf("guest_key not Base64URL(no pad): %v", err)
	}
	if len(k) != 32 {
		t.Fatalf("guest_key decodes to %d bytes, want 32", len(k))
	}

	var aesKey []byte
	if passphrase == "" || saltB64 == "" {
		aesKey = k
	} else {
		salt, err := base64.StdEncoding.DecodeString(saltB64)
		if err != nil {
			t.Fatalf("salt not standard Base64: %v", err)
		}
		pmat, err := pbkdf2.Key(sha256.New, passphrase, salt, 200000, 32)
		if err != nil {
			t.Fatalf("pbkdf2: %v", err)
		}
		ikm := append(append([]byte{}, k...), pmat...)
		aesKey, err = hkdf.Key(sha256.New, ikm, salt, "dragpass-guest-v1", 32)
		if err != nil {
			t.Fatalf("hkdf: %v", err)
		}
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		t.Fatalf("aes: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("gcm: %v", err)
	}
	pt, err := gcm.Open(nil, iv, ct, nil)
	if err != nil {
		t.Fatalf("guest viewer decrypt failed: %v", err)
	}
	return pt
}

// sealOrgToken mimics the Extension: AES-GCM-seal a plaintext directly with
// the raw Group DEK and return the (iv_b64, ciphertext_b64) the handler wants.
func sealOrgToken(t *testing.T, groupRaw, plaintext []byte) (ivB64, ctB64 string) {
	t.Helper()
	iv, ct, err := AESGCMSealSplit(groupRaw, plaintext)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	return base64.StdEncoding.EncodeToString(iv), base64.StdEncoding.EncodeToString(ct)
}

func TestHandleGroupTranscryptForGuest_RoundTrip_NoPassphrase(t *testing.T) {
	deps, _, _ := newTestDeps(t)
	handle, groupRaw := openSessionForFreshKey(t, deps)

	const sentinel = "GUEST_PLAINTEXT_SENTINEL_NO_PASS"
	ivB64, ctB64 := sealOrgToken(t, groupRaw, []byte(sentinel))

	resp := HandleGroupTranscryptForGuest(deps, proto.GroupTranscryptForGuestRequest{
		GroupHandle:   handle,
		IVB64:         ivB64,
		CiphertextB64: ctB64,
	})
	if !resp.Success {
		t.Fatalf("expected success, got error: %s", resp.Error)
	}
	data, ok := resp.Data.(proto.GroupTranscryptForGuestResponseData)
	if !ok {
		t.Fatalf("data type = %T, want GroupTranscryptForGuestResponseData", resp.Data)
	}

	// guest_key must be Base64URL(no pad) of 32B.
	k, err := base64.RawURLEncoding.DecodeString(data.GuestKey)
	if err != nil || len(k) != 32 {
		t.Fatalf("guest_key = %q not Base64URL(32B): err=%v len=%d", data.GuestKey, err, len(k))
	}
	// guest_ciphertext must carry a 12B IV prefix.
	payload, err := base64.StdEncoding.DecodeString(data.GuestCiphertext)
	if err != nil || len(payload) < 12+16 {
		t.Fatalf("guest_ciphertext malformed: err=%v len=%d", err, len(payload))
	}

	got := guestViewerDecrypt(t, data.GuestCiphertext, data.GuestKey, "", "")
	if string(got) != sentinel {
		t.Fatalf("round-trip mismatch: got %q want %q", got, sentinel)
	}
}

func TestHandleGroupTranscryptForGuest_RoundTrip_WithPassphrase(t *testing.T) {
	deps, _, _ := newTestDeps(t)
	handle, groupRaw := openSessionForFreshKey(t, deps)

	const sentinel = "GUEST_PLAINTEXT_SENTINEL_WITH_PASS"
	ivB64, ctB64 := sealOrgToken(t, groupRaw, []byte(sentinel))

	// The app generates the salt and sends it as standard Base64.
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		t.Fatalf("rand: %v", err)
	}
	saltB64 := base64.StdEncoding.EncodeToString(salt)
	const passphrase = "hunter2-guest-pass"

	resp := HandleGroupTranscryptForGuest(deps, proto.GroupTranscryptForGuestRequest{
		GroupHandle:    handle,
		IVB64:          ivB64,
		CiphertextB64:  ctB64,
		Passphrase:     passphrase,
		PassphraseSalt: saltB64,
	})
	if !resp.Success {
		t.Fatalf("expected success, got error: %s", resp.Error)
	}
	data := resp.Data.(proto.GroupTranscryptForGuestResponseData)

	// Wrong / missing passphrase must NOT decrypt (proves passphrase binding).
	func() {
		defer func() { _ = recover() }()
		wrong := guestViewerDecryptSoft(data.GuestCiphertext, data.GuestKey, "", "")
		if wrong != nil {
			t.Fatalf("K-only decrypt should fail for a passphrase-protected share")
		}
	}()

	got := guestViewerDecrypt(t, data.GuestCiphertext, data.GuestKey, passphrase, saltB64)
	if string(got) != sentinel {
		t.Fatalf("round-trip mismatch: got %q want %q", got, sentinel)
	}
}

// guestViewerDecryptSoft is the non-fatal variant used to assert a decrypt
// *fails*.
func guestViewerDecryptSoft(ciphertextB64, keyB64url, passphrase, saltB64 string) []byte {
	payload, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil || len(payload) < 12+16 {
		return nil
	}
	iv, ct := payload[:12], payload[12:]
	k, err := base64.RawURLEncoding.DecodeString(keyB64url)
	if err != nil {
		return nil
	}
	var aesKey []byte
	if passphrase == "" || saltB64 == "" {
		aesKey = k
	} else {
		salt, _ := base64.StdEncoding.DecodeString(saltB64)
		pmat, _ := pbkdf2.Key(sha256.New, passphrase, salt, 200000, 32)
		ikm := append(append([]byte{}, k...), pmat...)
		aesKey, _ = hkdf.Key(sha256.New, ikm, salt, "dragpass-guest-v1", 32)
	}
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil
	}
	pt, err := gcm.Open(nil, iv, ct, nil)
	if err != nil {
		return nil
	}
	return pt
}

// TestGuestTranscrypt_FixedVector — known-answer vector for frontend e2e
// cross-check. Feed the SAME K / salt / passphrase / plaintext into the
// admin SPA guest viewer (guest-share-crypto.ts) and it must produce/consume
// the same bytes.
//
// Fixed inputs:
//
//	K          = 0x00 0x01 .. 0x1f                 (Base64URL: AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8)
//	salt       = 0xa0 0xa1 .. 0xaf                 (Base64:    oKGio6SlpqeoqaqrrK2urw==)
//	iv         = 0x10 0x11 .. 0x1b
//	passphrase = "correct-horse-battery-staple"
//	plaintext  = "guest share fixed vector"
//	PBKDF2-SHA256(passphrase, salt, 200000, 32) → HKDF-SHA256(K‖pmat, salt,
//	  "dragpass-guest-v1", 32) derived AES key =
//	  fdcd8c9c9d95a7a57bf5a09e9aee8ec4f656c2636add0fbd76f09540e697c47f
func TestGuestTranscrypt_FixedVector(t *testing.T) {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i)
	}
	salt := make([]byte, 16)
	for i := range salt {
		salt[i] = byte(0xA0 + i)
	}
	const passphrase = "correct-horse-battery-staple"
	const plaintext = "guest share fixed vector"

	// deriveGuestAESKey (passphrase path) matches the documented golden key.
	const wantKeyHex = "fdcd8c9c9d95a7a57bf5a09e9aee8ec4f656c2636add0fbd76f09540e697c47f"
	derived, err := deriveGuestAESKey(k, passphrase, salt)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if got := hex.EncodeToString(derived); got != wantKeyHex {
		t.Fatalf("derived AES key = %s, want %s (guest-share-crypto.ts drift)", got, wantKeyHex)
	}

	// Golden ciphertexts (fixed iv 0x10..0x1b) must decrypt to the plaintext
	// via the viewer algorithm.
	const passphrasePathCipherB64 = "EBESExQVFhcYGRobFNSAFh+7n7ZubTHV1nLW8OfO4KNsgUvVG3oZGKKy18v+iXtKIXxePA=="
	const kOnlyCipherB64 = "EBESExQVFhcYGRobGov9ZT3pSdurB209aRARNrNwOGt4tjjDmW84sjqt8prW9WAwy/VtCw=="
	keyB64url := base64.RawURLEncoding.EncodeToString(k)
	saltB64 := base64.StdEncoding.EncodeToString(salt)

	if got := guestViewerDecrypt(t, passphrasePathCipherB64, keyB64url, passphrase, saltB64); string(got) != plaintext {
		t.Fatalf("passphrase-path vector decrypt = %q, want %q", got, plaintext)
	}
	if got := guestViewerDecrypt(t, kOnlyCipherB64, keyB64url, "", ""); string(got) != plaintext {
		t.Fatalf("K-only vector decrypt = %q, want %q", got, plaintext)
	}
}

// TestHandleGroupTranscryptForGuest_NoSecretEcho — plaintext, raw Group DEK,
// and derived key must never appear in the response envelope or the logger.
func TestHandleGroupTranscryptForGuest_NoSecretEcho(t *testing.T) {
	deps, log, _ := newTestDeps(t)
	handle, groupRaw := openSessionForFreshKey(t, deps)

	const sentinel = "GUEST_LEAK_SENTINEL_XYZ"
	ivB64, ctB64 := sealOrgToken(t, groupRaw, []byte(sentinel))
	groupRawB64 := base64.StdEncoding.EncodeToString(groupRaw)

	resp := HandleGroupTranscryptForGuest(deps, proto.GroupTranscryptForGuestRequest{
		GroupHandle:   handle,
		IVB64:         ivB64,
		CiphertextB64: ctB64,
	})
	if !resp.Success {
		t.Fatalf("expected success, got %s", resp.Error)
	}

	respJSON, _ := json.Marshal(resp)
	for _, banned := range []string{sentinel, groupRawB64, "plaintext", "group_dek"} {
		if strings.Contains(string(respJSON), banned) {
			t.Fatalf("response leaked %q: %s", banned, respJSON)
		}
	}
	for _, banned := range []string{sentinel, groupRawB64} {
		if log.Contains(banned) {
			t.Fatalf("logger leaked %q: %v", banned, log.Messages())
		}
	}
}

// TestHandleGroupTranscryptForGuest_RejectsBadInput — validation guards.
func TestHandleGroupTranscryptForGuest_RejectsBadInput(t *testing.T) {
	deps, _, _ := newTestDeps(t)
	handle, groupRaw := openSessionForFreshKey(t, deps)
	ivB64, ctB64 := sealOrgToken(t, groupRaw, []byte("x"))
	validSalt := base64.StdEncoding.EncodeToString(make([]byte, 16))

	cases := []struct {
		name string
		req  proto.GroupTranscryptForGuestRequest
		want string // substring expected in error
	}{
		{
			name: "passphrase without salt",
			req: proto.GroupTranscryptForGuestRequest{
				GroupHandle: handle, IVB64: ivB64, CiphertextB64: ctB64,
				Passphrase: "p",
			},
			want: "passphrase_salt",
		},
		{
			name: "salt without passphrase",
			req: proto.GroupTranscryptForGuestRequest{
				GroupHandle: handle, IVB64: ivB64, CiphertextB64: ctB64,
				PassphraseSalt: validSalt,
			},
			want: "passphrase_salt",
		},
		{
			name: "bad iv length",
			req: proto.GroupTranscryptForGuestRequest{
				GroupHandle:   handle,
				IVB64:         base64.StdEncoding.EncodeToString(make([]byte, 8)),
				CiphertextB64: ctB64,
			},
			want: "iv_b64",
		},
		{
			name: "bad handle",
			req: proto.GroupTranscryptForGuestRequest{
				GroupHandle: "short", IVB64: ivB64, CiphertextB64: ctB64,
			},
			want: "group_handle",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := HandleGroupTranscryptForGuest(deps, tc.req)
			if resp.Success {
				t.Fatalf("%s: expected rejection", tc.name)
			}
			if !strings.Contains(resp.Error, tc.want) {
				t.Fatalf("%s: error %q must mention %q", tc.name, resp.Error, tc.want)
			}
		})
	}
}

// TestHandleGroupTranscryptForGuest_BadHandle — an unregistered handle is a
// not-found error and no output is produced.
func TestHandleGroupTranscryptForGuest_UnknownSession(t *testing.T) {
	deps, _, _ := newTestDeps(t)
	resp := HandleGroupTranscryptForGuest(deps, proto.GroupTranscryptForGuestRequest{
		GroupHandle:   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		IVB64:         base64.StdEncoding.EncodeToString(make([]byte, 12)),
		CiphertextB64: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0}, 28)),
	})
	if resp.Success {
		t.Fatalf("expected failure on missing group session")
	}
}
