package crypto

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"testing"
)

func randAESKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return k
}

func TestAESGCM_Roundtrip(t *testing.T) {
	key := randAESKey(t)
	plaintext := []byte("hello dragpass recovery wrap")

	ct, err := AESGCMEncryptBase64(key, plaintext)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	pt, err := AESGCMDecryptBase64(key, ct)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	if !bytes.Equal(pt, plaintext) {
		t.Errorf("roundtrip mismatch: got %q, want %q", pt, plaintext)
	}
}

func TestAESGCM_DifferentIVEachCall(t *testing.T) {
	key := randAESKey(t)
	pt := []byte("same plaintext")

	a, _ := AESGCMEncryptBase64(key, pt)
	b, _ := AESGCMEncryptBase64(key, pt)

	if a == b {
		t.Errorf("expected different ciphertexts (random IV), got identical")
	}
}

func TestAESGCM_WrongKeyFails(t *testing.T) {
	key := randAESKey(t)
	other := randAESKey(t)
	pt := []byte("secret")

	ct, _ := AESGCMEncryptBase64(key, pt)
	if _, err := AESGCMDecryptBase64(other, ct); err == nil {
		t.Errorf("expected decrypt with wrong key to fail")
	}
}

func TestAESGCM_RejectsWrongKeyLength(t *testing.T) {
	short := make([]byte, 16)
	if _, err := AESGCMEncryptBase64(short, []byte("x")); err == nil {
		t.Errorf("expected encrypt with 16-byte key to fail")
	}
	if _, err := AESGCMDecryptBase64(short, "AAA"); err == nil {
		t.Errorf("expected decrypt with 16-byte key to fail")
	}
}

func TestAESGCM_OutputContainsIVPrefix(t *testing.T) {
	key := randAESKey(t)
	ct, err := AESGCMEncryptBase64(key, []byte("payload"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	raw, err := base64.StdEncoding.DecodeString(ct)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	// IV(12) + ciphertext(>=1) + tag(16) = at least 29
	if len(raw) < 12+1+16 {
		t.Errorf("ciphertext too short: %d", len(raw))
	}
}

func TestAESGCM_RejectsCorruptedCiphertext(t *testing.T) {
	key := randAESKey(t)
	ct, _ := AESGCMEncryptBase64(key, []byte("payload"))

	raw, _ := base64.StdEncoding.DecodeString(ct)
	// Flip a bit in the ciphertext portion (after IV)
	raw[15] ^= 0x01
	tampered := base64.StdEncoding.EncodeToString(raw)

	if _, err := AESGCMDecryptBase64(key, tampered); err == nil {
		t.Errorf("expected GCM auth failure on tampered ciphertext")
	}
}
