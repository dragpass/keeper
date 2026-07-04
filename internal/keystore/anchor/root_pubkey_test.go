package anchor

// root_pubkey_test.go — Root pubkey embedded/env/missing modes
// + signature verification.

import (
	stdcrypto "crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	keepercrypto "github.com/dragpass/keeper/internal/keystore/crypto"
)

// withTempRootPublicKey temporarily sets the package var
// rootPublicKeyPEMBase64 for the duration of the test, and restores it in
// t.Cleanup.
func withTempRootPublicKey(t *testing.T, pem string) {
	t.Helper()
	old := rootPublicKeyPEMBase64
	rootPublicKeyPEMBase64 = base64.StdEncoding.EncodeToString([]byte(pem))
	t.Cleanup(func() { rootPublicKeyPEMBase64 = old })
}

func generateRootKeypairForTest(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	kp, err := keepercrypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("generate keypair: %v", err)
	}
	priv, err := keepercrypto.ParsePrivateKey(kp.PrivateKey)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return priv, kp.PublicKey
}

func signRootPayloadForTest(t *testing.T, priv *rsa.PrivateKey, payload []byte) []byte {
	t.Helper()
	hashed := sha256.Sum256(payload)
	sig, err := rsa.SignPSS(rand.Reader, priv, stdcrypto.SHA256, hashed[:], keepercrypto.RSAPSSOptions())
	if err != nil {
		t.Fatalf("SignPSS: %v", err)
	}
	return sig
}

func TestRootPublicKeyPEM_EmptyByDefault(t *testing.T) {
	old := rootPublicKeyPEMBase64
	rootPublicKeyPEMBase64 = ""
	t.Cleanup(func() { rootPublicKeyPEMBase64 = old })

	pem, err := RootPublicKeyPEM()
	if err != nil {
		t.Fatalf("RootPublicKeyPEM err = %v", err)
	}
	if pem != "" {
		t.Errorf("empty embed should return empty PEM, got %q", pem)
	}
}

func TestComputeRootKeyFingerprint_Matches(t *testing.T) {
	pem := "-----BEGIN PUBLIC KEY-----\nFAKE\n-----END PUBLIC KEY-----\n"
	withTempRootPublicKey(t, pem)

	got, err := ComputeRootKeyFingerprint()
	if err != nil {
		t.Fatalf("compute: %v", err)
	}
	expected := sha256.Sum256([]byte(pem))
	want := "sha256:" + hex.EncodeToString(expected[:])
	if got != want {
		t.Errorf("fingerprint = %q, want %q", got, want)
	}
}

func TestVerifyServerKeyRootSignature_RoundTrip(t *testing.T) {
	priv, pubPEM := generateRootKeypairForTest(t)
	withTempRootPublicKey(t, pubPEM)

	payload := BuildServerKeyRootSigPayload(2, "DUMMY-PEM", 1700000000, 1800000000)
	sig := signRootPayloadForTest(t, priv, payload)

	if err := VerifyServerKeyRootSignature(payload, sig); err != nil {
		t.Errorf("verify failed: %v", err)
	}
}

func TestVerifyServerKeyRootSignature_RejectsWrongSig(t *testing.T) {
	priv, pubPEM := generateRootKeypairForTest(t)
	withTempRootPublicKey(t, pubPEM)

	payload := BuildServerKeyRootSigPayload(2, "DUMMY-PEM", 1700000000, 1800000000)
	otherPayload := BuildServerKeyRootSigPayload(2, "DUMMY-PEM", 1700000001, 1800000000) // different issuedUnix
	sig := signRootPayloadForTest(t, priv, otherPayload)

	err := VerifyServerKeyRootSignature(payload, sig)
	if err == nil {
		t.Errorf("expected verification failure with mismatched payload")
	}
	if !strings.Contains(err.Error(), "root signature verification failed") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestVerifyServerKeyRootSignature_RejectsWhenRootMissing(t *testing.T) {
	old := rootPublicKeyPEMBase64
	rootPublicKeyPEMBase64 = ""
	t.Cleanup(func() { rootPublicKeyPEMBase64 = old })

	err := VerifyServerKeyRootSignature([]byte("x"), []byte("x"))
	if err != ErrRootKeyNotConfigured {
		t.Errorf("missing root should return ErrRootKeyNotConfigured, got %v", err)
	}
}

func TestBuildServerKeyRootSigPayload_FormatStable(t *testing.T) {
	got := BuildServerKeyRootSigPayload(7, "PEM-BODY", 100, 200)
	want := "v1|7|PEM-BODY|100|200"
	if string(got) != want {
		t.Errorf("payload = %q, want %q", got, want)
	}
}
