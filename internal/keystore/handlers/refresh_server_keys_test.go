// refresh_server_keys_test.go — HandleRefreshServerKeys e2e verification.
//
// Coverage:
//  1. Validate — keys empty / 0 active / multiple actives / invalid status value
//  2. Root embedded: reject fingerprint mismatch
//  3. Root embedded: every key must have root_signature
//  4. Root embedded: reject bad signature
//  5. Root embedded: valid signature → updated_versions/active_version/root_verified=true
//  6. Root missing: skip signature verification + fingerprint TOFU pin
//  7. Verify the 4 Keychain slots are updated (versioned, active pointer,
//     legacy mirror, fingerprint pin)
//
// Migrated from the keystore root's refresh_server_keys_facade_test.go. All
// keychain helpers were updated to use deps's SecretStore directly.
// withTempRootPublicKey / generateRootKeypairForTest / signRootPayloadForTest
// live as helpers inside this file (originally in the root
// test_helpers_test.go).
package handlers

import (
	stdcrypto "crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/dragpass/keeper/config"
	"github.com/dragpass/keeper/internal/keystore/anchor"
	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/keychain"
)

// bootstrapServerKeyVersionForTest mirrors the unexported keychain.bootstrapServerKeyVersion
// (the immutable v1 anchor). Tests reference it for slot-cleanup symmetry.
const bootstrapServerKeyVersionForTest uint = 1

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

// resetServerKeySlots clears all server-key-related Keychain slots between
// refresh_server_keys_test cases. Operates on the test's SecretStore directly.
func resetServerKeySlots(t *testing.T, store keychain.SecretStore) {
	t.Helper()
	_ = keychain.DeleteServerPublicKey(store)
	_ = keychain.DeleteServerPublicKeyForVersion(store, 1)
	_ = keychain.DeleteServerPublicKeyForVersion(store, 2)
	_ = keychain.DeleteServerPublicKeyForVersion(store, 3)
	// active version pointer + root pubkey fingerprint also reset
	_ = store.Delete(config.Service, config.DragPassServerPublicKeyActiveVersion)
	_ = store.Delete(config.Service, config.DragPassServerRootPublicKeyFingerprint)
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

func TestRefreshServerKeysRequest_Validate(t *testing.T) {
	cases := []struct {
		name string
		req  RefreshServerKeysRequest
		want string
	}{
		{
			name: "empty",
			req:  RefreshServerKeysRequest{},
			want: "keys is empty",
		},
		{
			name: "no active",
			req: RefreshServerKeysRequest{
				Keys: []SystemServerKeyEntry{
					{Version: 1, PublicKeyPEM: "p", Status: "deprecated"},
				},
			},
			want: "exactly one active key, got 0",
		},
		{
			name: "two active",
			req: RefreshServerKeysRequest{
				Keys: []SystemServerKeyEntry{
					{Version: 1, PublicKeyPEM: "p1", Status: "active"},
					{Version: 2, PublicKeyPEM: "p2", Status: "active"},
				},
			},
			want: "exactly one active key, got 2",
		},
		{
			name: "version 0",
			req: RefreshServerKeysRequest{
				Keys: []SystemServerKeyEntry{
					{Version: 0, PublicKeyPEM: "p", Status: "active"},
				},
			},
			want: "version must be >= 1",
		},
		{
			name: "empty pem",
			req: RefreshServerKeysRequest{
				Keys: []SystemServerKeyEntry{
					{Version: 1, PublicKeyPEM: "", Status: "active"},
				},
			},
			want: "public_key_pem is empty",
		},
		{
			name: "bad status",
			req: RefreshServerKeysRequest{
				Keys: []SystemServerKeyEntry{
					{Version: 1, PublicKeyPEM: "p", Status: "revoked"},
				},
			},
			want: "status invalid",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.req.Validate()
			if err == nil {
				t.Fatalf("expected error containing %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want substring %q", err, tc.want)
			}
		})
	}
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
	legacy, _ := keychain.GetServerPublicKey(store)
	if legacy != pemV2 {
		t.Errorf("legacy mirror = %q, want active v2 PEM", legacy)
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

func TestHandleRefreshServerKeys_RootMissing_SkipsVerification(t *testing.T) {
	deps, _, store := newTestDeps(t)
	resetServerKeySlots(t, store)

	// Root not embedded — env-var path empty.
	// (The anchor package's rootPublicKeyPEMBase64 variable cannot be mutated
	// externally. Setting the KEEPER_ROOT_PUBLIC_KEY_BASE64 env var to empty
	// is enough to take the same branch as a production build with no embed.)
	t.Setenv("KEEPER_ROOT_PUBLIC_KEY_BASE64", "")

	pem := "-----BEGIN PUBLIC KEY-----\nFREE\n-----END PUBLIC KEY-----\n"
	req := RefreshServerKeysRequest{
		Keys: []SystemServerKeyEntry{
			{
				Version:      1,
				PublicKeyPEM: pem,
				IssuedAt:     time.Unix(1700000000, 0),
				ExpiresAt:    time.Unix(1800000000, 0),
				Status:       "active",
				// no signature
			},
		},
		RootPublicKeyFingerprint: "sha256:server-only-pin",
	}

	resp := HandleRefreshServerKeys(deps, req)
	if !resp.Success {
		t.Fatalf("root-missing should accept unsigned response, got error: %s", resp.Error)
	}
	data := resp.Data.(RefreshServerKeysResponseData)
	if data.RootVerified {
		t.Errorf("root_verified should be false in missing-root mode")
	}
	pinned, _ := keychain.GetRootPublicKeyFingerprint(store)
	if pinned != "sha256:server-only-pin" {
		t.Errorf("fingerprint should be TOFU-pinned, got %q", pinned)
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
