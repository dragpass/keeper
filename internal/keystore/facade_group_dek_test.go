// facade_group_dek_test.go: dispatch-level behavior of wrapgroupdek +
// group_session_open. Covers the team encrypt key invariant round-trip
// (wrap → open into a handle) + 32B length enforcement + malformed PEM
// reject + clear error when the active private key is missing + reject
// ciphertext wrapped with a different keypair.
//
// The raw-returning unwrapgroupdek action was removed; group_session_open
// (RSA-OAEP unwrap into a Keeper-held opaque handle) is now the unwrap path.
package keystore

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// TestHandleRequest_WrapGroupDEK_ThenGroupSessionOpen verifies the core
// team-encrypt invariant end-to-end after the raw-return unwrap action was
// removed: "wrap(group_dek, pub) → group_session_open(_, priv)" succeeds.
//
// group_session_open RSA-OAEP-unwraps with the active private key into a
// Keeper-held opaque handle, so a successful open proves the wrap is a valid
// ciphertext the private key can recover (the raw Group DEK never crosses IPC).
//
// Scenario:
//  1. The Keeper has an active keypair (saved directly).
//  2. Assume the Extension generated a 32B Group DEK (use a fixed value).
//  3. wrapgroupdek: wrap the Group DEK with the Keeper's public key
//     (recipient is self).
//  4. group_session_open: unwrap with the Keeper's private key → returns a
//     non-empty handle.
func TestHandleRequest_WrapGroupDEK_ThenGroupSessionOpen(t *testing.T) {
	app := newFacadeTestApp()

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

	// 1. wrapgroupdek — wrap to my own public key.
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

	// 2. group_session_open — unwrap with the active private key into a handle.
	openMsg := fmt.Sprintf(
		`{"action":"group_session_open","payload":{"encrypted_group_dek":%q}}`,
		wrapData.EncryptedGroupDEK,
	)
	openResp := app.HandleRequest([]byte(openMsg))
	if !openResp.Success {
		t.Fatalf("group_session_open failed: %s", openResp.Error)
	}
	var openData struct {
		GroupHandle string `json:"group_handle"`
	}
	raw2, _ := json.Marshal(openResp.Data)
	json.Unmarshal(raw2, &openData)
	if openData.GroupHandle == "" {
		t.Fatal("group_handle should not be empty")
	}
	t.Cleanup(func() {
		app.GroupSessions.Close(openData.GroupHandle)
	})
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

// TestHandleRequest_GroupSessionOpen_NoPrivateKey verifies open fails
// with a clear error when no active private key is in the Keychain.
func TestHandleRequest_GroupSessionOpen_NoPrivateKey(t *testing.T) {
	app := newFacadeTestApp()

	msg := `{"action":"group_session_open","payload":{"encrypted_group_dek":"aGVsbG8="}}`
	resp := app.HandleRequest([]byte(msg))
	if resp.Success {
		t.Error("group_session_open should fail without active private key")
	}
}

// TestHandleRequest_GroupSessionOpen_WrongCiphertext verifies RSA-OAEP
// decryption fails when a correct key is present but the ciphertext was
// wrapped with a different key.
func TestHandleRequest_GroupSessionOpen_WrongCiphertext(t *testing.T) {
	// Save keypair A to the Keychain.
	kpA, _ := GenerateRSAKeyPair()
	app := newFacadeTestApp()
	app.savePrivateKey(kpA.PrivateKey)
	app.savePublicKey(kpA.PublicKey)

	// Don't save keypair B; wrap a ciphertext with its public key and then try to open.
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

	// Try to open a ciphertext wrapped with B's key using A's private key → must fail.
	openMsg := fmt.Sprintf(
		`{"action":"group_session_open","payload":{"encrypted_group_dek":%q}}`,
		wrapData.EncryptedGroupDEK,
	)
	openResp := app.HandleRequest([]byte(openMsg))
	if openResp.Success {
		t.Error("group_session_open should fail when ciphertext was wrapped with a different public key")
	}
}
