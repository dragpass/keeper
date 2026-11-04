package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"testing"
)

func TestRewrapKeyFingerprintNormalizesPEMWithoutChangingStoredPin(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	canonical := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	variant := append(append([]byte(nil), canonical...), '\n')
	want := sha256.Sum256(der)
	for _, input := range [][]byte{canonical, variant} {
		got, err := RewrapKeyFingerprint(string(input))
		if err != nil || got != hex.EncodeToString(want[:]) {
			t.Fatalf("rewrap fingerprint = %q, %v", got, err)
		}
	}
	if AccountKeyFingerprint(canonical) == AccountKeyFingerprint(variant) {
		t.Fatal("stored PEM-byte pin unexpectedly normalized")
	}
	if _, err := RewrapKeyFingerprint("invalid"); err == nil {
		t.Fatal("invalid public key accepted")
	}
}
