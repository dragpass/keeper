// wrap_active_private_key_test.go — regression guard for
// HandleWrapActivePrivateKey (Recovery key re-issue) in
// wrap_active_private_key.go.
//
// The handler fetches the active Keeper privkey PEM from the Keychain and
// AES-GCM-wraps it under the supplied 32B wrap_key, returning
// iv(12) || ciphertext Base64.
package handlers

import (
	"encoding/base64"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// TestWrapActivePrivateKey_Roundtrip: wrapping the stored active privkey PEM
// under wrap_key yields output that AES-GCM-decrypts back to the exact PEM.
func TestWrapActivePrivateKey_Roundtrip(t *testing.T) {
	deps, _, store := newTestDeps(t)

	const pem = "-----BEGIN PRIVATE KEY-----\nMOCK-KEEPER-ACTIVE-PEM-CONTENT\n-----END PRIVATE KEY-----"
	if err := keychain.SavePrivateKey(store, pem); err != nil {
		t.Fatalf("SavePrivateKey: %v", err)
	}

	wrapKey := make([]byte, 32)
	for i := range wrapKey {
		wrapKey[i] = byte(0x40 + i)
	}
	resp := HandleWrapActivePrivateKey(deps, proto.WrapActivePrivateKeyRequest{
		WrapKeyB64: base64.StdEncoding.EncodeToString(wrapKey),
	})
	if !resp.Success {
		t.Fatalf("wrap active private key failed: %s", resp.Error)
	}
	data := resp.Data.(proto.WrapActivePrivateKeyResponseData)
	if data.WrappedKeeperB64 == "" {
		t.Fatal("wrapped_keeper_b64 should not be empty")
	}

	got, err := crypto.AESGCMDecryptBase64(wrapKey, data.WrappedKeeperB64)
	if err != nil {
		t.Fatalf("decrypt wrapped keeper: %v", err)
	}
	if string(got) != pem {
		t.Error("unwrapped PEM must equal the stored active private key")
	}
}

// TestWrapActivePrivateKey_DoesNotEchoPrivateKey: the plaintext PEM material
// must never reach the logger.
func TestWrapActivePrivateKey_DoesNotEchoPrivateKey(t *testing.T) {
	deps, log, store := newTestDeps(t)

	const sentinel = "-----BEGIN PRIVATE KEY-----\nSECRET_PRIVATE_KEY_MATERIAL_DO_NOT_LEAK\n-----END PRIVATE KEY-----"
	if err := keychain.SavePrivateKey(store, sentinel); err != nil {
		t.Fatalf("SavePrivateKey: %v", err)
	}

	wrapKey := make([]byte, 32)
	resp := HandleWrapActivePrivateKey(deps, proto.WrapActivePrivateKeyRequest{
		WrapKeyB64: base64.StdEncoding.EncodeToString(wrapKey),
	})
	if !resp.Success {
		t.Fatalf("wrap should succeed: %s", resp.Error)
	}
	if log.Contains(sentinel) {
		t.Fatalf("logger leaked private key material: %v", log.Messages())
	}
}
