package crypto

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

// Pinned on the ariadne side too. A drift here means the two repos stop
// recognising each other's leaf keys without anything failing loudly.
const mlsLeafZeroKeyFingerprint = "66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925"

func TestMLSLeafSignatureKeyFingerprint_GoldenZeroKey(t *testing.T) {
	got, err := MLSLeafSignatureKeyFingerprint(make(ed25519.PublicKey, ed25519.PublicKeySize))
	if err != nil {
		t.Fatalf("fingerprint of 32 zero bytes: %v", err)
	}
	if got != mlsLeafZeroKeyFingerprint {
		t.Fatalf("fingerprint = %s, want %s", got, mlsLeafZeroKeyFingerprint)
	}
}

// The leaf and account fingerprints are both hex SHA-256, so a leaf key routed
// through AccountKeyFingerprint would still look right. These fail if either
// function is made to call the other: the leaf one must refuse an encoding the
// account one happily hashes, and the two must disagree on the same key.
func TestMLSLeafSignatureKeyFingerprint_IsNotTheAccountKeyFingerprint(t *testing.T) {
	public, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})

	if fp, err := MLSLeafSignatureKeyFingerprint(publicPEM); err == nil {
		t.Fatalf("leaf fingerprint accepted a PEM and returned %s", fp)
	}
	if _, err := MLSLeafSignatureKeyFingerprint(public[:31]); err == nil {
		t.Fatal("leaf fingerprint accepted a 31-byte key")
	}

	leaf, err := MLSLeafSignatureKeyFingerprint(public)
	if err != nil {
		t.Fatal(err)
	}
	if leaf == AccountKeyFingerprint(publicPEM) {
		t.Fatal("leaf fingerprint of the raw key equals the account fingerprint of its PEM")
	}
}
