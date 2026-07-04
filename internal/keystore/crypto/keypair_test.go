package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
)

func TestGenerateRSAKeyPair(t *testing.T) {
	kp, err := GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("GenerateRSAKeyPair() error = %v", err)
	}

	if !strings.Contains(kp.PrivateKey, "PRIVATE KEY") {
		t.Error("private key should be in PEM format")
	}
	if !strings.Contains(kp.PublicKey, "PUBLIC KEY") {
		t.Error("public key should be in PEM format")
	}
}

func TestGenerateRSAKeyPair_Unique(t *testing.T) {
	kp1, _ := GenerateRSAKeyPair()
	kp2, _ := GenerateRSAKeyPair()

	if kp1.PrivateKey == kp2.PrivateKey {
		t.Error("two generated key pairs should be different")
	}
}

func TestParsePrivateKey(t *testing.T) {
	kp, _ := GenerateRSAKeyPair()

	priv, err := ParsePrivateKey(kp.PrivateKey)
	if err != nil {
		t.Fatalf("ParsePrivateKey() error = %v", err)
	}
	if priv.N.BitLen() != 2048 {
		t.Errorf("key size = %d bits, want 2048", priv.N.BitLen())
	}
}

func TestParsePrivateKey_Invalid(t *testing.T) {
	tests := []struct {
		name string
		pem  string
	}{
		{"empty", ""},
		{"garbage", "not-a-pem"},
		{"wrong type", "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParsePrivateKey(tt.pem)
			if err == nil {
				t.Error("expected error for invalid PEM")
			}
		})
	}
}

func TestParsePublicKey(t *testing.T) {
	kp, _ := GenerateRSAKeyPair()

	pub, err := ParsePublicKey(kp.PublicKey)
	if err != nil {
		t.Fatalf("ParsePublicKey() error = %v", err)
	}
	if pub.N.BitLen() != 2048 {
		t.Errorf("key size = %d bits, want 2048", pub.N.BitLen())
	}
}

func TestParsePublicKey_Invalid(t *testing.T) {
	_, err := ParsePublicKey("not-a-pem")
	if err == nil {
		t.Error("expected error for invalid PEM")
	}
}

func TestPublicKeyToPEM_Roundtrip(t *testing.T) {
	kp, _ := GenerateRSAKeyPair()
	pub, _ := ParsePublicKey(kp.PublicKey)

	pemStr, err := PublicKeyToPEM(pub)
	if err != nil {
		t.Fatalf("PublicKeyToPEM() error = %v", err)
	}

	pub2, err := ParsePublicKey(pemStr)
	if err != nil {
		t.Fatalf("re-parse error = %v", err)
	}

	if pub.N.Cmp(pub2.N) != 0 {
		t.Error("public key roundtrip failed: keys differ")
	}
}

func TestSignAndVerify_Roundtrip(t *testing.T) {
	kp, _ := GenerateRSAKeyPair()
	priv, _ := ParsePrivateKey(kp.PrivateKey)
	pub, _ := ParsePublicKey(kp.PublicKey)

	data := "hello-world-challenge"
	sig, err := SignData(priv, data)
	if err != nil {
		t.Fatalf("SignData() error = %v", err)
	}

	if err := VerifySignature(pub, data, sig); err != nil {
		t.Errorf("VerifySignature() error = %v", err)
	}
}

func TestVerifySignature_TamperedData(t *testing.T) {
	kp, _ := GenerateRSAKeyPair()
	priv, _ := ParsePrivateKey(kp.PrivateKey)
	pub, _ := ParsePublicKey(kp.PublicKey)

	sig, _ := SignData(priv, "original")

	if err := VerifySignature(pub, "tampered", sig); err == nil {
		t.Error("expected verification failure for tampered data")
	}
}

func TestVerifySignature_WrongKey(t *testing.T) {
	kp1, _ := GenerateRSAKeyPair()
	kp2, _ := GenerateRSAKeyPair()

	priv1, _ := ParsePrivateKey(kp1.PrivateKey)
	pub2, _ := ParsePublicKey(kp2.PublicKey)

	sig, _ := SignData(priv1, "data")

	if err := VerifySignature(pub2, "data", sig); err == nil {
		t.Error("expected verification failure with wrong key")
	}
}

func TestDecryptData_Roundtrip(t *testing.T) {
	kp, _ := GenerateRSAKeyPair()
	priv, _ := ParsePrivateKey(kp.PrivateKey)
	pub, _ := ParsePublicKey(kp.PublicKey)

	plaintext := "secret-session-code-ABCD-1234"

	// Encrypt with public key (RSA-OAEP)
	encrypted, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, []byte(plaintext), nil)
	if err != nil {
		t.Fatalf("EncryptOAEP error = %v", err)
	}

	// Decrypt with private key
	decrypted, err := DecryptData(priv, encrypted)
	if err != nil {
		t.Fatalf("DecryptData() error = %v", err)
	}

	if string(decrypted) != plaintext {
		t.Errorf("decrypted = %q, want %q", string(decrypted), plaintext)
	}
}

func TestDecryptData_InvalidCiphertext(t *testing.T) {
	kp, _ := GenerateRSAKeyPair()
	priv, _ := ParsePrivateKey(kp.PrivateKey)

	_, err := DecryptData(priv, []byte("not-encrypted-data"))
	if err == nil {
		t.Error("expected error for invalid ciphertext")
	}
}

func TestSignData_Base64Roundtrip(t *testing.T) {
	// Tests the same flow as actions.go: sign → base64 → decode → verify
	kp, _ := GenerateRSAKeyPair()
	priv, _ := ParsePrivateKey(kp.PrivateKey)
	pub, _ := ParsePublicKey(kp.PublicKey)

	data := "test-alias"
	sigBytes, _ := SignData(priv, data)
	sigB64 := base64.StdEncoding.EncodeToString(sigBytes)

	decoded, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		t.Fatalf("base64 decode error = %v", err)
	}

	if err := VerifySignature(pub, data, decoded); err != nil {
		t.Errorf("signature verification after base64 roundtrip failed: %v", err)
	}
}
