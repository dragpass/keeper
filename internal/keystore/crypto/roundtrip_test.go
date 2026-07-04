// Crypto service boundary — primitive round-trip worked examples.
//
// **Purpose of this file:** crypto function tests prefer real primitive
// round-trips over mocks. This file collects worked examples that verify the
// three primitives AES-GCM / RSA-OAEP / RSA-PSS directly without mocks.
//
// **Defects this test catches:**
//   - Regressions where a primitive causes silent corruption (e.g. open
//     succeeds even after ciphertext modification)
//   - Regressions where tamper-detection branches break
//   - Regressions in key length / IV length / algorithm parameters
//   - Regressions in the Base64 envelope format (IV(12B) || ciphertext_with_tag)
//
// An algorithm change (e.g. AES-GCM → ChaCha20) is a wire format change,
// so this file at a glance demonstrates that the algorithm picker is fixed
// here.
package crypto

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"testing"
)

// AES-GCM round trip — same key seal/open returns plaintext.
func TestCryptoRoundTrip_AESGCM_SealOpen(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	plaintext := []byte("DragPass crypto boundary worked example payload")

	envelope, err := AESGCMEncryptBase64(key, plaintext)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if envelope == "" {
		t.Fatalf("empty envelope")
	}

	decrypted, err := AESGCMDecryptBase64(key, envelope)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("round-trip mismatch: got %q, want %q", decrypted, plaintext)
	}
}

// AES-GCM tamper detection — modifying ciphertext rejects.
func TestCryptoRoundTrip_AESGCM_TamperedCiphertextRejected(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	envelope, err := AESGCMEncryptBase64(key, []byte("integrity-protected message body — long enough"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	// Tamper at the binary level: decode → flip one byte in the ciphertext
	// region → re-encode. After IV(12B) is the ciphertext+tag region. Pick
	// the middle index to safely flip one bit.
	raw, err := base64.StdEncoding.DecodeString(envelope)
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}
	if len(raw) < 13 {
		t.Fatalf("envelope too short: %d", len(raw))
	}
	tamperIdx := 12 + (len(raw)-12)/2 // one byte in the middle of ciphertext
	raw[tamperIdx] ^= 0xFF
	tampered := base64.StdEncoding.EncodeToString(raw)
	if tampered == envelope {
		t.Fatalf("test setup: tamper changed nothing")
	}

	if _, err := AESGCMDecryptBase64(key, tampered); err == nil {
		t.Fatalf("expected GCM auth tag failure on tampered ciphertext")
	}
}

// AES-GCM key mismatch — wrong key rejects.
func TestCryptoRoundTrip_AESGCM_WrongKeyRejected(t *testing.T) {
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	_, _ = rand.Read(key1)
	_, _ = rand.Read(key2)

	envelope, err := AESGCMEncryptBase64(key1, []byte("encrypted with key1"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if _, err := AESGCMDecryptBase64(key2, envelope); err == nil {
		t.Fatalf("expected failure when decrypt key != encrypt key")
	}
}

// AES-GCM rejects keys of wrong length.
func TestCryptoRoundTrip_AESGCM_RejectsBadKeyLength(t *testing.T) {
	cases := []int{0, 16, 24, 31, 33, 64}
	for _, n := range cases {
		key := make([]byte, n)
		if _, err := AESGCMEncryptBase64(key, []byte("x")); err == nil {
			t.Fatalf("expected rejection for key length %d", n)
		}
	}
}

// RSA round trip — generate, sign with private, verify with public.
func TestCryptoRoundTrip_RSA_SignVerify(t *testing.T) {
	kp, err := GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("GenerateRSAKeyPair: %v", err)
	}
	priv, err := ParsePrivateKey(kp.PrivateKey)
	if err != nil {
		t.Fatalf("ParsePrivateKey: %v", err)
	}
	pub, err := ParsePublicKey(kp.PublicKey)
	if err != nil {
		t.Fatalf("ParsePublicKey: %v", err)
	}

	const payload = "challenge-token-12345"
	sig, err := SignData(priv, payload)
	if err != nil {
		t.Fatalf("SignData: %v", err)
	}
	if err := VerifySignature(pub, payload, sig); err != nil {
		t.Fatalf("VerifySignature: %v", err)
	}
}

// RSA-PSS tamper detection — modifying signature rejects.
func TestCryptoRoundTrip_RSA_TamperedSignatureRejected(t *testing.T) {
	kp, _ := GenerateRSAKeyPair()
	priv, _ := ParsePrivateKey(kp.PrivateKey)
	pub, _ := ParsePublicKey(kp.PublicKey)

	const payload = "challenge-token"
	sig, _ := SignData(priv, payload)
	if len(sig) == 0 {
		t.Fatalf("empty signature")
	}

	// Flip the first byte.
	tampered := append([]byte{}, sig...)
	tampered[0] ^= 0xFF

	if err := VerifySignature(pub, payload, tampered); err == nil {
		t.Fatalf("expected RSA-PSS verification failure on tampered signature")
	}
}

// RSA-PSS payload mismatch — different data rejects.
func TestCryptoRoundTrip_RSA_PayloadMismatchRejected(t *testing.T) {
	kp, _ := GenerateRSAKeyPair()
	priv, _ := ParsePrivateKey(kp.PrivateKey)
	pub, _ := ParsePublicKey(kp.PublicKey)

	sig, _ := SignData(priv, "payload-A")
	if err := VerifySignature(pub, "payload-B", sig); err == nil {
		t.Fatalf("expected verification failure when payload differs")
	}
}

// RSA-OAEP round trip — public-key encrypt / private-key decrypt.
func TestCryptoRoundTrip_RSA_OAEPEncryptDecrypt(t *testing.T) {
	kp, _ := GenerateRSAKeyPair()
	priv, _ := ParsePrivateKey(kp.PrivateKey)
	pub, _ := ParsePublicKey(kp.PublicKey)

	plaintext := []byte("group-dek-32-bytes-fake--padding")
	if len(plaintext) != 32 {
		t.Fatalf("test setup: 32B payload required, got %d", len(plaintext))
	}

	ciphertext, err := EncryptData(pub, plaintext)
	if err != nil {
		t.Fatalf("EncryptData: %v", err)
	}
	if bytes.Equal(ciphertext, plaintext) {
		t.Fatalf("ciphertext must differ from plaintext")
	}

	decrypted, err := DecryptData(priv, ciphertext)
	if err != nil {
		t.Fatalf("DecryptData: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("RSA-OAEP round-trip mismatch")
	}
}

// RSA-OAEP wrong-key rejection — different recipient cannot decrypt.
func TestCryptoRoundTrip_RSA_OAEPWrongKeyRejected(t *testing.T) {
	kp1, _ := GenerateRSAKeyPair()
	kp2, _ := GenerateRSAKeyPair()
	pub1, _ := ParsePublicKey(kp1.PublicKey)
	priv2, _ := ParsePrivateKey(kp2.PrivateKey)

	plaintext := []byte("for-kp1-only-32bytes-fake-padding")[:32]
	ciphertext, err := EncryptData(pub1, plaintext)
	if err != nil {
		t.Fatalf("EncryptData: %v", err)
	}

	// Attempt to decrypt with kp2's private key → reject.
	if _, err := DecryptData(priv2, ciphertext); err == nil {
		t.Fatalf("expected decrypt failure with wrong recipient")
	}
}
