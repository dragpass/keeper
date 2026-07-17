// facade_group_dek_test.go: dispatch-level behavior of group_session_open.
// Covers the team encrypt key invariant round-trip (RSA-OAEP wrap → open into
// a handle) + a clear error when the active private key is missing + reject of
// a ciphertext wrapped with a different keypair.
//
// The raw-input wrapgroupdek action was removed; the wrap fixture below is a
// direct crypto.EncryptData call (same convention as facade_composite_dek_test.go).
// The raw-returning unwrapgroupdek action was also removed; group_session_open
// (RSA-OAEP unwrap into a Keeper-held opaque handle) is now the unwrap path.
package keystore

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
)

// wrapGroupDEKForTest RSA-OAEP-SHA256 wraps a raw Group DEK to a public key
// PEM, standing in for the removed wrapgroupdek action when a test needs a
// wrapped Group DEK ciphertext as a fixture.
func wrapGroupDEKForTest(t *testing.T, pubPEM string, groupDEK []byte) string {
	t.Helper()
	pub, err := ParsePublicKey(pubPEM)
	if err != nil {
		t.Fatalf("ParsePublicKey: %v", err)
	}
	wrapped, err := EncryptData(pub, groupDEK)
	if err != nil {
		t.Fatalf("EncryptData: %v", err)
	}
	return base64.StdEncoding.EncodeToString(wrapped)
}

// TestHandleRequest_GroupSessionOpen_RoundTrip verifies the core team-encrypt
// invariant end-to-end: "wrap(group_dek, pub) → group_session_open(_, priv)"
// succeeds.
//
// group_session_open RSA-OAEP-unwraps with the active private key into a
// Keeper-held opaque handle, so a successful open proves the wrap is a valid
// ciphertext the private key can recover (the raw Group DEK never crosses IPC).
//
// Scenario:
//  1. The Keeper has an active keypair (saved directly).
//  2. Assume the Extension generated a 32B Group DEK (use a fixed value).
//  3. Wrap the Group DEK with the Keeper's public key (recipient is self).
//  4. group_session_open: unwrap with the Keeper's private key → returns a
//     non-empty handle.
func TestHandleRequest_GroupSessionOpen_RoundTrip(t *testing.T) {
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

	// 1. Wrap to my own public key.
	encryptedGroupDEK := wrapGroupDEKForTest(t, kp.PublicKey, groupDEK)

	// 2. group_session_open — unwrap with the active private key into a handle.
	openMsg := fmt.Sprintf(
		`{"action":"group_session_open","payload":{"encrypted_group_dek":%q}}`,
		encryptedGroupDEK,
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
	encryptedGroupDEK := wrapGroupDEKForTest(t, kpB.PublicKey, groupDEK)

	// Try to open a ciphertext wrapped with B's key using A's private key → must fail.
	openMsg := fmt.Sprintf(
		`{"action":"group_session_open","payload":{"encrypted_group_dek":%q}}`,
		encryptedGroupDEK,
	)
	openResp := app.HandleRequest([]byte(openMsg))
	if openResp.Success {
		t.Error("group_session_open should fail when ciphertext was wrapped with a different public key")
	}
}
