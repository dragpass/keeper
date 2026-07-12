package crypto

import (
	"bytes"
	"testing"
)

func TestHybridWrapUnwrap_RoundTrip(t *testing.T) {
	kp, err := GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("GenerateRSAKeyPair: %v", err)
	}
	pub, err := ParsePublicKey(kp.PublicKey)
	if err != nil {
		t.Fatalf("ParsePublicKey: %v", err)
	}
	priv, err := ParsePrivateKey(kp.PrivateKey)
	if err != nil {
		t.Fatalf("ParsePrivateKey: %v", err)
	}

	// Payload larger than the RSA-OAEP-2048 limit (190 bytes) — the whole point
	// of hybrid wrapping. A Shamir share of a PEM is ~1.7 KB.
	payload := bytes.Repeat([]byte{0xAB}, 2000)

	wrappedKey, ciphertext, err := HybridWrap(pub, payload)
	if err != nil {
		t.Fatalf("HybridWrap: %v", err)
	}
	got, err := HybridUnwrap(priv, wrappedKey, ciphertext)
	if err != nil {
		t.Fatalf("HybridUnwrap: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("roundtrip mismatch")
	}
}

func TestHybridUnwrap_WrongKeyFails(t *testing.T) {
	kp1, _ := GenerateRSAKeyPair()
	kp2, _ := GenerateRSAKeyPair()
	pub1, _ := ParsePublicKey(kp1.PublicKey)
	priv2, _ := ParsePrivateKey(kp2.PrivateKey)

	wrappedKey, ciphertext, err := HybridWrap(pub1, []byte("secret-share-bytes"))
	if err != nil {
		t.Fatalf("HybridWrap: %v", err)
	}
	if _, err := HybridUnwrap(priv2, wrappedKey, ciphertext); err == nil {
		t.Fatalf("expected unwrap with wrong key to fail")
	}
}
