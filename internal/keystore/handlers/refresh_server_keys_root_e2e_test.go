//go:build keeper_e2e

package handlers

// Root-embedded refresh_server_keys cases. They need a root key the test
// generated, which only a keeper_e2e build reads from
// KEEPER_ROOT_PUBLIC_KEY_BASE64; a release build takes the root key from
// -ldflags alone (anchor/root_pubkey_release.go).

import (
	stdcrypto "crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/dragpass/keeper/internal/keystore/anchor"
	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/keychain"
)

// withTempRootPublicKey sets KEEPER_ROOT_PUBLIC_KEY_BASE64 for the duration
// of the test so that anchor.RootPublicKeyPEM() returns the given PEM.
// t.Setenv handles cleanup automatically.
func withTempRootPublicKey(t *testing.T, pem string) {
	t.Helper()
	t.Setenv("KEEPER_ROOT_PUBLIC_KEY_BASE64", base64.StdEncoding.EncodeToString([]byte(pem)))
}

// generateRootKeypairForTest creates a fresh RSA keypair for signing tests.
func generateRootKeypairForTest(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	kp, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("generate keypair: %v", err)
	}
	priv, err := crypto.ParsePrivateKey(kp.PrivateKey)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return priv, kp.PublicKey
}

// signRootPayloadForTest signs payload with priv using RSA-PSS-SHA256, the
// same options anchor.VerifyServerKeyRootSignature checks against.
func signRootPayloadForTest(t *testing.T, priv *rsa.PrivateKey, payload []byte) []byte {
	t.Helper()
	hashed := sha256.Sum256(payload)
	sig, err := rsa.SignPSS(rand.Reader, priv, stdcrypto.SHA256, hashed[:], crypto.RSAPSSOptions())
	if err != nil {
		t.Fatalf("SignPSS: %v", err)
	}
	return sig
}

func makeKeyEntryWithRootSig(t *testing.T, version uint, pem string, rootPriv *rsa.PrivateKey, status string) SystemServerKeyEntry {
	t.Helper()
	issued := time.Unix(1700000000, 0).UTC()
	expires := time.Unix(1800000000, 0).UTC()
	entry := SystemServerKeyEntry{
		Version:      version,
		PublicKeyPEM: pem,
		IssuedAt:     issued,
		ExpiresAt:    expires,
		Status:       status,
	}
	if rootPriv != nil {
		payload := anchor.BuildServerKeyRootSigPayload(version, pem, issued.Unix(), expires.Unix())
		sig := signRootPayloadForTest(t, rootPriv, payload)
		entry.RootSignature = base64.StdEncoding.EncodeToString(sig)
	}
	return entry
}

func TestHandleRefreshServerKeys_RootEmbedded_RoundTrip(t *testing.T) {
	deps, _, store := newTestDeps(t)
	resetServerKeySlots(t, store)
	rootPriv, rootPubPEM := generateRootKeypairForTest(t)
	withTempRootPublicKey(t, rootPubPEM)

	embeddedFp, err := anchor.ComputeRootKeyFingerprint()
	if err != nil {
		t.Fatalf("compute root fp: %v", err)
	}

	pemV1 := "-----BEGIN PUBLIC KEY-----\nKEY-V1\n-----END PUBLIC KEY-----\n"
	pemV2 := "-----BEGIN PUBLIC KEY-----\nKEY-V2\n-----END PUBLIC KEY-----\n"

	req := RefreshServerKeysRequest{
		Keys: []SystemServerKeyEntry{
			makeKeyEntryWithRootSig(t, 1, pemV1, rootPriv, "deprecated"),
			makeKeyEntryWithRootSig(t, 2, pemV2, rootPriv, "active"),
		},
		RootPublicKeyFingerprint: embeddedFp,
	}

	resp := HandleRefreshServerKeys(deps, req)
	if !resp.Success {
		t.Fatalf("refresh failed: %s", resp.Error)
	}
	data := resp.Data.(RefreshServerKeysResponseData)
	if data.ActiveVersion != 2 {
		t.Errorf("active = %d, want 2", data.ActiveVersion)
	}
	if !data.RootVerified {
		t.Errorf("root_verified should be true")
	}

	// Keychain slot checks
	if got, _ := keychain.GetServerPublicKeyByVersion(store, 1); got != pemV1 {
		t.Errorf("v1 slot = %q, want %q", got, pemV1)
	}
	if got, _ := keychain.GetServerPublicKeyByVersion(store, 2); got != pemV2 {
		t.Errorf("v2 slot = %q, want %q", got, pemV2)
	}
	v, _ := keychain.GetActiveServerKeyVersion(store)
	if v != 2 {
		t.Errorf("active version pointer = %d, want 2", v)
	}
	pinned, _ := keychain.GetRootPublicKeyFingerprint(store)
	if pinned != embeddedFp {
		t.Errorf("fingerprint pin = %q, want %q", pinned, embeddedFp)
	}
}

func TestHandleRefreshServerKeys_RootEmbedded_RejectsFingerprintMismatch(t *testing.T) {
	deps, _, store := newTestDeps(t)
	resetServerKeySlots(t, store)
	rootPriv, rootPubPEM := generateRootKeypairForTest(t)
	withTempRootPublicKey(t, rootPubPEM)

	pem := "-----BEGIN PUBLIC KEY-----\nK\n-----END PUBLIC KEY-----\n"
	req := RefreshServerKeysRequest{
		Keys: []SystemServerKeyEntry{
			makeKeyEntryWithRootSig(t, 1, pem, rootPriv, "active"),
		},
		RootPublicKeyFingerprint: "sha256:WRONG",
	}

	resp := HandleRefreshServerKeys(deps, req)
	if resp.Success {
		t.Fatalf("expected fingerprint mismatch rejection")
	}
	if !strings.Contains(resp.Error, "fingerprint mismatch") {
		t.Errorf("error = %q, want fingerprint mismatch", resp.Error)
	}
}

func TestHandleRefreshServerKeys_RootEmbedded_RequiresAllSignatures(t *testing.T) {
	deps, _, store := newTestDeps(t)
	resetServerKeySlots(t, store)
	rootPriv, rootPubPEM := generateRootKeypairForTest(t)
	withTempRootPublicKey(t, rootPubPEM)
	embeddedFp, _ := anchor.ComputeRootKeyFingerprint()

	pemV1 := "-----BEGIN PUBLIC KEY-----\nK1\n-----END PUBLIC KEY-----\n"
	pemV2 := "-----BEGIN PUBLIC KEY-----\nK2\n-----END PUBLIC KEY-----\n"

	// v2 is missing its signature
	v2Entry := makeKeyEntryWithRootSig(t, 2, pemV2, rootPriv, "active")
	v2Entry.RootSignature = ""

	req := RefreshServerKeysRequest{
		Keys: []SystemServerKeyEntry{
			makeKeyEntryWithRootSig(t, 1, pemV1, rootPriv, "deprecated"),
			v2Entry,
		},
		RootPublicKeyFingerprint: embeddedFp,
	}

	resp := HandleRefreshServerKeys(deps, req)
	if resp.Success {
		t.Fatalf("expected rejection when signature missing")
	}
	if !strings.Contains(resp.Error, "root_signature missing") {
		t.Errorf("error = %q, want missing-signature message", resp.Error)
	}
}

func TestHandleRefreshServerKeys_RootEmbedded_RejectsBadSignature(t *testing.T) {
	deps, _, store := newTestDeps(t)
	resetServerKeySlots(t, store)
	rootPriv, rootPubPEM := generateRootKeypairForTest(t)
	withTempRootPublicKey(t, rootPubPEM)
	embeddedFp, _ := anchor.ComputeRootKeyFingerprint()

	pem := "-----BEGIN PUBLIC KEY-----\nK\n-----END PUBLIC KEY-----\n"
	entry := makeKeyEntryWithRootSig(t, 1, pem, rootPriv, "active")
	// Replace with garbage signature
	entry.RootSignature = base64.StdEncoding.EncodeToString([]byte("not-a-real-signature-bytes-padded-to-256-bytes-for-rsa-pss-and-also-extra-padding-here-for-rsa-2048"))

	req := RefreshServerKeysRequest{
		Keys:                     []SystemServerKeyEntry{entry},
		RootPublicKeyFingerprint: embeddedFp,
	}

	resp := HandleRefreshServerKeys(deps, req)
	if resp.Success {
		t.Fatalf("expected rejection of bad signature")
	}
	if !strings.Contains(resp.Error, "root signature verify") {
		t.Errorf("error = %q, want signature verify failure", resp.Error)
	}
}

func TestHandleRefreshServerKeys_RootEmbedded_RejectsMissingFingerprint(t *testing.T) {
	deps, _, store := newTestDeps(t)
	resetServerKeySlots(t, store)
	rootPriv, rootPubPEM := generateRootKeypairForTest(t)
	withTempRootPublicKey(t, rootPubPEM)

	pem := "-----BEGIN PUBLIC KEY-----\nK\n-----END PUBLIC KEY-----\n"
	req := RefreshServerKeysRequest{
		Keys: []SystemServerKeyEntry{
			makeKeyEntryWithRootSig(t, 1, pem, rootPriv, "active"),
		},
		// fingerprint missing
	}

	resp := HandleRefreshServerKeys(deps, req)
	if resp.Success {
		t.Fatalf("expected rejection when fingerprint absent in root-embedded mode")
	}
	if !strings.Contains(resp.Error, "no fingerprint") {
		t.Errorf("error = %q, want no-fingerprint message", resp.Error)
	}
}

func TestHandleRefreshServerKeys_VersionedChallengeAfterRefresh(t *testing.T) {
	// Simulation: after refresh makes v2 active, if SignChallengeToken
	// specifies ServerKeyVersion=2, it must verify with the v2 key.
	deps, log, store := newTestDeps(t)
	resetServerKeySlots(t, store)
	rootPriv, rootPubPEM := generateRootKeypairForTest(t)
	withTempRootPublicKey(t, rootPubPEM)
	embeddedFp, _ := anchor.ComputeRootKeyFingerprint()

	// v1 = bootstrap hardcoded key (real PEM)
	if err := keychain.EnsureServerPublicKey(store, log); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	pemV1, _ := keychain.GetServerPublicKeyByVersion(store, 1)

	// generate new v2 keypair
	v2KP, _ := crypto.GenerateRSAKeyPair()
	pemV2 := v2KP.PublicKey

	// register v2 as active via refresh
	req := RefreshServerKeysRequest{
		Keys: []SystemServerKeyEntry{
			makeKeyEntryWithRootSig(t, 1, pemV1, rootPriv, "deprecated"),
			makeKeyEntryWithRootSig(t, 2, pemV2, rootPriv, "active"),
		},
		RootPublicKeyFingerprint: embeddedFp,
	}
	resp := HandleRefreshServerKeys(deps, req)
	if !resp.Success {
		t.Fatalf("refresh failed: %s", resp.Error)
	}

	// version=2 explicit → returns v2 PEM
	got2, err := keychain.GetServerPublicKeyForVersion(store, 2)
	if err != nil || got2 != pemV2 {
		t.Errorf("v=2 lookup mismatch: got %q err=%v", got2, err)
	}
	// version=0 fallback → returns active (= v2)
	got0, err := keychain.GetServerPublicKeyForVersion(store, 0)
	if err != nil || got0 != pemV2 {
		t.Errorf("v=0 fallback mismatch: got %q err=%v", got0, err)
	}
	// version=1 → deprecated slot still preserved
	got1, err := keychain.GetServerPublicKeyByVersion(store, 1)
	if err != nil || got1 != pemV1 {
		t.Errorf("v=1 deprecated slot mismatch: got %q err=%v", got1, err)
	}

	// suppress unused — bootstrapServerKeyVersionForTest is for reference
	// inside this package only, not for external tests.
	_ = bootstrapServerKeyVersionForTest
}
