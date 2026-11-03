package changetrack

import (
	"crypto/rand"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/crypto"
)

func sealForTest(dek, plain, aad []byte) ([]byte, []byte, error) {
	return crypto.SealAESGCM(rand.Reader, dek, plain, aad)
}

// openTagForTest returns a record's tag for in-memory comparison only.
func openTagForTest(t *testing.T, dek []byte, s Scope, rec Sealed) []byte {
	t.Helper()
	aad, err := recordAAD(s, rec.DekVersion, rec.Seq)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := crypto.OpenAESGCM(dek, rec.IV, rec.Ciphertext, aad)
	if err != nil {
		t.Fatal("open failed")
	}
	return plain[1+recordKeyBytes:]
}

// openKeyForTest returns a record's comparison key for in-memory comparison only.
func openKeyForTest(t *testing.T, dek []byte, s Scope, rec Sealed) []byte {
	t.Helper()
	aad, err := recordAAD(s, rec.DekVersion, rec.Seq)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := crypto.OpenAESGCM(dek, rec.IV, rec.Ciphertext, aad)
	if err != nil {
		t.Fatal("open failed")
	}
	return plain[1 : 1+recordKeyBytes]
}
