// dek_rewrap_test.go — composite-action tests
// (HandleDEKRewrapWithOldKey production round-trip).
//
// Two core guarantees of HandleDEKRewrapWithOldKey:
//
//  1. **security gate** — rejects calls without a verified server signature
//     over challenge_token.
//  2. **crypto round-trip** — a Group DEK wrapped with one RSA keypair and
//     rewrapped by the composite action with a different RSA keypair must
//     decrypt with the new key to the same original value.
//
// Also directly verifies that the response serialization leaks no traces of
// the raw Group DEK.
//
// old_private_key_pem is replaced by recovery_handle. The helper
// openTestRecoverySession registers the PEM with the store and returns a handle.
//
// Migrated from the keystore root's dek_rewrap_facade_test.go. The root used
// saveServerPublicKey + a temporary keypair's PSS signature for
// server-signature verification, but in the handlers package the deps's
// ServerKeyVerifier is injected directly as AlwaysOKVerifier /
// AlwaysFailVerifier.
package handlers

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// openTestRecoverySession registers raw PEM bytes with deps's
// RecoverySessions and returns a handle. Auto-closed on test end.
func openTestRecoverySession(t *testing.T, deps Deps, rawPEM string) string {
	t.Helper()
	rawCopy := []byte(rawPEM)
	handle, _, err := deps.RecoverySessions.Open(rawCopy)
	if err != nil {
		t.Fatalf("openTestRecoverySession: %v", err)
	}
	t.Cleanup(func() {
		deps.RecoverySessions.Close(handle)
	})
	return handle
}

func TestHandleDEKRewrapWithOldKey_Validation(t *testing.T) {
	deps, _, _ := newTestDeps(t)
	cases := []struct {
		name string
		req  proto.DEKRewrapWithOldKeyRequest
	}{
		{"missing challenge", proto.DEKRewrapWithOldKeyRequest{Signature: "s", RecoveryHandle: "h", EncryptedGroupDEK: "e", NewPublicKey: "pk"}},
		{"missing signature", proto.DEKRewrapWithOldKeyRequest{ChallengeToken: "c", RecoveryHandle: "h", EncryptedGroupDEK: "e", NewPublicKey: "pk"}},
		{"missing handle", proto.DEKRewrapWithOldKeyRequest{ChallengeToken: "c", Signature: "s", EncryptedGroupDEK: "e", NewPublicKey: "pk"}},
		{"missing encrypted", proto.DEKRewrapWithOldKeyRequest{ChallengeToken: "c", Signature: "s", RecoveryHandle: "h", NewPublicKey: "pk"}},
		{"missing new pub", proto.DEKRewrapWithOldKeyRequest{ChallengeToken: "c", Signature: "s", RecoveryHandle: "h", EncryptedGroupDEK: "e"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := HandleDEKRewrapWithOldKey(deps, tc.req)
			if resp.Success {
				t.Errorf("expected validation failure for %q, got success", tc.name)
			}
		})
	}
}

func TestHandleDEKRewrapWithOldKey_BadServerSignature(t *testing.T) {
	deps, _, _ := newTestDepsFailVerify(t, errors.New("server signature verification failed: stub"))

	// 256B garbage signature (RSA-2048 PSS is 256B). base64 decode passes;
	// AlwaysFailVerifier must reject.
	garbage := make([]byte, 256)
	for i := range garbage {
		garbage[i] = byte(i)
	}
	req := proto.DEKRewrapWithOldKeyRequest{
		ChallengeToken: "challenge-x",
		Signature:      base64.StdEncoding.EncodeToString(garbage),
		// 32B Base64 (44 chars) — passes requireHandle so we reach the server-sig check.
		RecoveryHandle:    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		EncryptedGroupDEK: base64.StdEncoding.EncodeToString([]byte("doesnt-matter")),
		NewPublicKey:      "-----BEGIN PUBLIC KEY-----\nfake\n-----END PUBLIC KEY-----",
	}
	resp := HandleDEKRewrapWithOldKey(deps, req)
	if resp.Success {
		t.Error("expected dek_rewrap_with_old_key to reject bad server signature")
	}
	if !strings.Contains(resp.Error, "server signature verification failed") {
		t.Errorf("error should mention server signature failure, got: %q", resp.Error)
	}
}

// TestHandleDEKRewrapWithOldKey_RejectsBadHandle: unregistered handles must
// be clearly rejected (re-open signal to the Extension).
func TestHandleDEKRewrapWithOldKey_RejectsBadHandle(t *testing.T) {
	deps, _, _ := newTestDeps(t) // AlwaysOKVerifier — verify passes, store lookup rejects

	newKP, _ := crypto.GenerateRSAKeyPair()
	resp := HandleDEKRewrapWithOldKey(deps, proto.DEKRewrapWithOldKeyRequest{
		ChallengeToken: "test-bad-handle",
		Signature:      base64.StdEncoding.EncodeToString(make([]byte, 256)),
		// 32B Base64 (44 chars) — passes Validate; store lookup rejects.
		RecoveryHandle:    "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
		EncryptedGroupDEK: base64.StdEncoding.EncodeToString([]byte("doesnt-matter")),
		NewPublicKey:      newKP.PublicKey,
	})
	if resp.Success {
		t.Error("expected failure for nonexistent recovery_handle")
	}
	if !strings.Contains(resp.Error, "recovery session") {
		t.Errorf("error should mention recovery session, got: %q", resp.Error)
	}
}

// TestHandleDEKRewrapWithOldKey_RoundTrip: verifies the composite action
// performs unwrap+rewrap correctly by decrypting the wrapped result with the
// new key and comparing to the original.
func TestHandleDEKRewrapWithOldKey_RoundTrip(t *testing.T) {
	deps, _, _ := newTestDeps(t) // AlwaysOKVerifier

	// 1. Two user RSA keypairs — old (used for wrap) / new (decrypts rewrap output)
	oldKP, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("GenerateRSAKeyPair (old): %v", err)
	}
	newKP, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("GenerateRSAKeyPair (new): %v", err)
	}

	// 2. Deterministic 32B Group DEK + RSA-OAEP wrap with old public key
	groupDEK := make([]byte, 32)
	for i := range groupDEK {
		groupDEK[i] = byte(0xC0 + i)
	}
	oldPub, err := crypto.ParsePublicKey(oldKP.PublicKey)
	if err != nil {
		t.Fatalf("ParsePublicKey (old): %v", err)
	}
	encryptedOld, err := crypto.EncryptData(oldPub, groupDEK)
	if err != nil {
		t.Fatalf("EncryptData (old): %v", err)
	}
	encryptedOldB64 := base64.StdEncoding.EncodeToString(encryptedOld)

	// 3. register old PEM with recovery session store → issue handle
	handle := openTestRecoverySession(t, deps, oldKP.PrivateKey)

	// 4. invoke composite action (use handle)
	req := proto.DEKRewrapWithOldKeyRequest{
		ChallengeToken:    "test-challenge-token",
		Signature:         base64.StdEncoding.EncodeToString(make([]byte, 256)),
		RecoveryHandle:    handle,
		EncryptedGroupDEK: encryptedOldB64,
		NewPublicKey:      newKP.PublicKey,
	}
	resp := HandleDEKRewrapWithOldKey(deps, req)
	if !resp.Success {
		t.Fatalf("HandleDEKRewrapWithOldKey failed: %s", resp.Error)
	}

	var data proto.DEKRewrapWithOldKeyResponseData
	raw, _ := json.Marshal(resp.Data)
	_ = json.Unmarshal(raw, &data)
	if data.NewEncryptedGroupDEK == "" {
		t.Fatal("new_encrypted_group_dek should not be empty")
	}

	// 5. decrypt with new private key and compare to original Group DEK — round-trip correctness
	newPriv, err := crypto.ParsePrivateKey(newKP.PrivateKey)
	if err != nil {
		t.Fatalf("ParsePrivateKey (new): %v", err)
	}
	newEncryptedRaw, err := base64.StdEncoding.DecodeString(data.NewEncryptedGroupDEK)
	if err != nil {
		t.Fatalf("decode new_encrypted: %v", err)
	}
	decrypted, err := crypto.DecryptData(newPriv, newEncryptedRaw)
	if err != nil {
		t.Fatalf("DecryptData (new): %v", err)
	}
	if len(decrypted) != 32 {
		t.Fatalf("decrypted length = %d, want 32", len(decrypted))
	}
	for i := range groupDEK {
		if decrypted[i] != groupDEK[i] {
			t.Fatalf("decrypted[%d] = %#x, want %#x — rewrap corrupted Group DEK",
				i, decrypted[i], groupDEK[i])
		}
	}
}

// TestHandleDEKRewrapWithOldKey_NoRawInResponse: the raw Group DEK Base64
// pattern must not leak anywhere in the response object's serialization.
func TestHandleDEKRewrapWithOldKey_NoRawInResponse(t *testing.T) {
	deps, _, _ := newTestDeps(t) // AlwaysOKVerifier

	oldKP, _ := crypto.GenerateRSAKeyPair()
	newKP, _ := crypto.GenerateRSAKeyPair()

	// Deterministic raw Group DEK — fixed prefix so the Base64 pattern matches
	groupDEK := []byte{
		0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
		0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
		0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
		0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
	}
	rawB64 := base64.StdEncoding.EncodeToString(groupDEK)

	oldPub, _ := crypto.ParsePublicKey(oldKP.PublicKey)
	encryptedOld, _ := crypto.EncryptData(oldPub, groupDEK)

	handle := openTestRecoverySession(t, deps, oldKP.PrivateKey)
	resp := HandleDEKRewrapWithOldKey(deps, proto.DEKRewrapWithOldKeyRequest{
		ChallengeToken:    "no-leak-challenge",
		Signature:         base64.StdEncoding.EncodeToString(make([]byte, 256)),
		RecoveryHandle:    handle,
		EncryptedGroupDEK: base64.StdEncoding.EncodeToString(encryptedOld),
		NewPublicKey:      newKP.PublicKey,
	})
	if !resp.Success {
		t.Fatalf("HandleDEKRewrapWithOldKey failed: %s", resp.Error)
	}

	jsonBytes, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("json.Marshal(resp): %v", err)
	}
	// the raw Group DEK Base64 pattern must not leak into the response.
	if strings.Contains(string(jsonBytes), rawB64) {
		t.Errorf("raw group DEK Base64 leaked into response: %s", string(jsonBytes))
	}
	// Also: the 0xDEADBEEF hex pattern must not leak (guards other encodings)
	if strings.Contains(strings.ToUpper(string(jsonBytes)), "DEADBEEF") {
		t.Errorf("raw group DEK hex pattern leaked into response: %s", string(jsonBytes))
	}
}

// Compile guard: avoid an unused-package warning for rsa
var _ = (*rsa.PublicKey)(nil)
