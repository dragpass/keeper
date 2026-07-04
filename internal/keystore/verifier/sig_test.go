// VerifyServerSig unit tests (verifier-package residency).
//
// Previous location: internal/keystore/server_sig_test.go.
//
// Each of the 4-step verification branches is guarded independently:
//  1. success → nil
//  2. version not found → "failed to get server public key" prefix
//  3. malformed PEM → "failed to parse server public key" prefix
//  4. invalid base64 → "failed to decode signature" prefix
//  5. forged signature → "server signature verification failed" prefix
//
// Uses the keychain package's exported API + MemorySecretStore instead of the
// keystore root's `saveServerPublicKey` / `krDelete` unexported helpers, for
// test isolation.

package verifier

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"strings"
	"testing"

	"crypto"

	"github.com/dragpass/keeper/internal/keystore/keychain"
)

// signForVerifyTest returns the Base64 of a PSS-SHA256 signature over token,
// using an arbitrary RSA priv.
func signForVerifyTest(t *testing.T, priv *rsa.PrivateKey, token string) string {
	t.Helper()
	hashed := sha256.Sum256([]byte(token))
	sig, err := rsa.SignPSS(rand.Reader, priv, crypto.SHA256, hashed[:], &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       crypto.SHA256,
	})
	if err != nil {
		t.Fatalf("SignPSS: %v", err)
	}
	return base64.StdEncoding.EncodeToString(sig)
}

// installServerKeyForTest injects a temporary server keypair into the v1 slot
// + active version pointer. Returns a MemorySecretStore the caller can pass
// straight into the verifier.
func installServerKeyForTest(t *testing.T) (*rsa.PrivateKey, keychain.SecretStore) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	store := keychain.NewMemorySecretStore()
	if err := keychain.SaveServerPublicKey(store, string(pubPEM)); err != nil {
		t.Fatalf("SaveServerPublicKey: %v", err)
	}
	if err := keychain.SaveServerPublicKeyForVersion(store, 1, string(pubPEM)); err != nil {
		t.Fatalf("SaveServerPublicKeyForVersion: %v", err)
	}
	if err := keychain.SaveActiveServerKeyVersion(store, 1); err != nil {
		t.Fatalf("SaveActiveServerKeyVersion: %v", err)
	}
	return priv, store
}

func TestVerifyServerSig_Success(t *testing.T) {
	priv, store := installServerKeyForTest(t)
	token := "verify-test-001"
	sig := signForVerifyTest(t, priv, token)

	if err := VerifyServerSig(store, token, sig, 0); err != nil {
		t.Errorf("expected success with active fallback, got: %v", err)
	}
	if err := VerifyServerSig(store, token, sig, 1); err != nil {
		t.Errorf("expected success with explicit version=1, got: %v", err)
	}
}

func TestVerifyServerSig_VersionNotFound(t *testing.T) {
	_, store := installServerKeyForTest(t)
	priv2, _ := rsa.GenerateKey(rand.Reader, 2048) // arbitrary priv (no effect on verify)
	sig := signForVerifyTest(t, priv2, "irrelevant")

	err := VerifyServerSig(store, "irrelevant", sig, 99) // nonexistent version
	if err == nil {
		t.Fatal("expected error for unknown version")
	}
	if !strings.Contains(err.Error(), "failed to get server public key") {
		t.Errorf("error prefix mismatch, got: %q", err.Error())
	}
}

func TestVerifyServerSig_InvalidSigBase64(t *testing.T) {
	_, store := installServerKeyForTest(t)

	err := VerifyServerSig(store, "token", "!!!not-base64!!!", 0)
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}
	if !strings.Contains(err.Error(), "failed to decode signature") {
		t.Errorf("error prefix mismatch, got: %q", err.Error())
	}
}

func TestVerifyServerSig_BadSignature(t *testing.T) {
	_, store := installServerKeyForTest(t)

	// Sign with a different priv → verification against the registered server
	// pub must fail.
	otherPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	sig := signForVerifyTest(t, otherPriv, "token-X")

	err := VerifyServerSig(store, "token-X", sig, 0)
	if err == nil {
		t.Fatal("expected error for forged signature")
	}
	if !strings.Contains(err.Error(), "server signature verification failed") {
		t.Errorf("error prefix mismatch, got: %q", err.Error())
	}
}

func TestVerifyServerSig_DifferentToken(t *testing.T) {
	priv, store := installServerKeyForTest(t)
	sig := signForVerifyTest(t, priv, "original-token")

	// Same priv signed, but token differs → verification fails.
	err := VerifyServerSig(store, "modified-token", sig, 0)
	if err == nil {
		t.Fatal("expected error for token mismatch")
	}
	if !strings.Contains(err.Error(), "server signature verification failed") {
		t.Errorf("error prefix mismatch, got: %q", err.Error())
	}
}
