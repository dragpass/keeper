// facade_group_dek_test.go: dispatch-level behavior of wrapgroupdek /
// unwrapgroupdek actions. Covers the team encrypt/decrypt key invariant
// round-trip + 32B length enforcement + malformed PEM reject + clear
// error when the active private key is missing + reject ciphertext
// wrapped with a different keypair.
package keystore

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// TestHandleRequest_WrapUnwrapGroupDEK_RoundTrip verifies the core
// team-encrypt/decrypt invariant
// "wrap(group_dek, pub) → unwrap(_, priv) == group_dek" end-to-end.
//
// Scenario:
//  1. The Keeper has a keypair (signup-like state, with active key set
//     via signalias).
//  2. Assume the Extension generated a 32B Group DEK (use a fixed value).
//  3. wrapgroupdek: wrap the Group DEK with the Keeper's public key
//     (recipient is self).
//  4. unwrapgroupdek: decrypt with the Keeper's private key → must equal
//     the original.
func TestHandleRequest_WrapUnwrapGroupDEK_RoundTrip(t *testing.T) {
	app := newFacadeTestApp()

	// Keypair setup — signalias creates a pending keypair, but promoting
	// it to active is done by savesessioncode. A pending-only state
	// isn't suitable for the unwrap test, so we could go through
	// generatekeypair, but the simplest thing is to create a KeyPair and
	// save it directly.
	kp, err := GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("GenerateRSAKeyPair: %v", err)
	}
	if err := app.savePrivateKey(kp.PrivateKey); err != nil {
		t.Fatalf("savePrivateKey: %v", err)
	}
	if err := app.savePublicKey(kp.PublicKey); err != nil {
		t.Fatalf("savePublicKey: %v", err)
	}

	// Generate a 32B Group DEK (deterministic value).
	groupDEK := make([]byte, 32)
	for i := range groupDEK {
		groupDEK[i] = byte(0xA0 + i)
	}
	groupDEKB64 := base64.StdEncoding.EncodeToString(groupDEK)

	// 1. wrapgroupdek
	wrapMsg := fmt.Sprintf(
		`{"action":"wrapgroupdek","payload":{"group_dek_b64":%q,"recipient_public_key":%q}}`,
		groupDEKB64,
		kp.PublicKey,
	)
	wrapResp := app.HandleRequest([]byte(wrapMsg))
	if !wrapResp.Success {
		t.Fatalf("wrapgroupdek failed: %s", wrapResp.Error)
	}
	var wrapData WrapGroupDEKResponseData
	raw, _ := json.Marshal(wrapResp.Data)
	json.Unmarshal(raw, &wrapData)
	if wrapData.EncryptedGroupDEK == "" {
		t.Fatal("encrypted_group_dek should not be empty")
	}

	// 2. unwrapgroupdek — same Keeper's private key is in the Keychain
	unwrapMsg := fmt.Sprintf(
		`{"action":"unwrapgroupdek","payload":{"encrypted_group_dek":%q}}`,
		wrapData.EncryptedGroupDEK,
	)
	unwrapResp := app.HandleRequest([]byte(unwrapMsg))
	if !unwrapResp.Success {
		t.Fatalf("unwrapgroupdek failed: %s", unwrapResp.Error)
	}
	var unwrapData UnwrapGroupDEKResponseData
	raw2, _ := json.Marshal(unwrapResp.Data)
	json.Unmarshal(raw2, &unwrapData)

	// 3. Confirm the unwrap result matches the original Group DEK
	decoded, err := base64.StdEncoding.DecodeString(unwrapData.GroupDEKB64)
	if err != nil {
		t.Fatalf("failed to decode unwrap result: %v", err)
	}
	if len(decoded) != 32 {
		t.Fatalf("decoded length = %d, want 32", len(decoded))
	}
	for i := 0; i < 32; i++ {
		if decoded[i] != groupDEK[i] {
			t.Fatalf("round-trip mismatch at byte %d: got %02x, want %02x", i, decoded[i], groupDEK[i])
		}
	}
}

// TestHandleRequest_WrapGroupDEK_InvalidLength verifies the handler
// rejects a group_dek that isn't 32 bytes (AES-256 key-length
// enforcement).
func TestHandleRequest_WrapGroupDEK_InvalidLength(t *testing.T) {
	app := newFacadeTestApp()
	kp, err := GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("GenerateRSAKeyPair: %v", err)
	}

	// Assume 16 bytes (AES-128) — must be rejected.
	shortDEK := make([]byte, 16)
	shortDEKB64 := base64.StdEncoding.EncodeToString(shortDEK)

	msg := fmt.Sprintf(
		`{"action":"wrapgroupdek","payload":{"group_dek_b64":%q,"recipient_public_key":%q}}`,
		shortDEKB64,
		kp.PublicKey,
	)
	resp := app.HandleRequest([]byte(msg))
	if resp.Success {
		t.Error("wrapgroupdek should reject non-32-byte group_dek")
	}
	if !strings.Contains(resp.Error, "32 bytes") {
		t.Errorf("expected error mentioning 32 bytes, got: %s", resp.Error)
	}
}

// TestHandleRequest_WrapGroupDEK_InvalidPublicKey verifies a malformed
// PEM is rejected.
func TestHandleRequest_WrapGroupDEK_InvalidPublicKey(t *testing.T) {
	app := newFacadeTestApp()
	groupDEK := make([]byte, 32)
	groupDEKB64 := base64.StdEncoding.EncodeToString(groupDEK)

	msg := fmt.Sprintf(
		`{"action":"wrapgroupdek","payload":{"group_dek_b64":%q,"recipient_public_key":"not-a-pem"}}`,
		groupDEKB64,
	)
	resp := app.HandleRequest([]byte(msg))
	if resp.Success {
		t.Error("wrapgroupdek should reject malformed public key")
	}
}

// TestHandleRequest_UnwrapGroupDEK_NoPrivateKey verifies unwrap fails
// with a clear error when no active private key is in the Keychain.
func TestHandleRequest_UnwrapGroupDEK_NoPrivateKey(t *testing.T) {
	app := newFacadeTestApp()

	msg := `{"action":"unwrapgroupdek","payload":{"encrypted_group_dek":"aGVsbG8="}}`
	resp := app.HandleRequest([]byte(msg))
	if resp.Success {
		t.Error("unwrapgroupdek should fail without active private key")
	}
}

// TestHandleRequest_UnwrapGroupDEK_WrongCiphertext verifies RSA-OAEP
// decryption fails when a correct key is present but the ciphertext was
// wrapped with a different key.
func TestHandleRequest_UnwrapGroupDEK_WrongCiphertext(t *testing.T) {
	// Save keypair A to the Keychain.
	kpA, _ := GenerateRSAKeyPair()
	app := newFacadeTestApp()
	app.savePrivateKey(kpA.PrivateKey)
	app.savePublicKey(kpA.PublicKey)

	// Don't save keypair B; wrap a ciphertext with its public key and then try to unwrap.
	kpB, _ := GenerateRSAKeyPair()
	groupDEK := make([]byte, 32)
	for i := range groupDEK {
		groupDEK[i] = byte(i)
	}
	groupDEKB64 := base64.StdEncoding.EncodeToString(groupDEK)

	wrapMsg := fmt.Sprintf(
		`{"action":"wrapgroupdek","payload":{"group_dek_b64":%q,"recipient_public_key":%q}}`,
		groupDEKB64,
		kpB.PublicKey,
	)
	wrapResp := app.HandleRequest([]byte(wrapMsg))
	if !wrapResp.Success {
		t.Fatalf("wrapgroupdek setup failed: %s", wrapResp.Error)
	}
	raw, _ := json.Marshal(wrapResp.Data)
	var wrapData WrapGroupDEKResponseData
	json.Unmarshal(raw, &wrapData)

	// Try to unwrap a ciphertext wrapped with B's key using A's private key → must fail.
	unwrapMsg := fmt.Sprintf(
		`{"action":"unwrapgroupdek","payload":{"encrypted_group_dek":%q}}`,
		wrapData.EncryptedGroupDEK,
	)
	unwrapResp := app.HandleRequest([]byte(unwrapMsg))
	if unwrapResp.Success {
		t.Error("unwrap should fail when ciphertext was wrapped with a different public key")
	}
}
