// facade_dispatch_test.go: baseline HandleRequest dispatcher behavior.
// Collects light dispatch-path checks for Ping / UnknownAction /
// InvalidJSON / DeviceKey delete+status+ensure / five SignAlias variants /
// SignAliasWithTimestamp / GetPublicKey / GetServerPublicKey / etc. in
// one file.
package keystore

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/keychain"
)

func TestHandleRequest_Ping(t *testing.T) {
	app := newFacadeTestApp()
	msg := `{"action":"ping"}`
	resp := app.HandleRequest([]byte(msg))

	if !resp.Success {
		t.Errorf("ping failed: %s", resp.Error)
	}
}

func TestHandleRequest_UnknownAction(t *testing.T) {
	app := newFacadeTestApp()
	msg := `{"action":"doesnotexist"}`
	resp := app.HandleRequest([]byte(msg))

	if resp.Success {
		t.Error("expected failure for unknown action")
	}
	if resp.Error == "" {
		t.Error("expected error message for unknown action")
	}
}

// Actions removed once no client called them answer an old client the way any
// unknown action does: the unsupported code, the request id echoed, nothing
// run. A chat state one is no longer gated either, so it gets this answer
// rather than chat_runtime_busy whoever holds the lease.
func TestHandleRequest_RemovedActionsAnswerUnsupported(t *testing.T) {
	app := newFacadeTestApp()
	for _, action := range []string{
		"chat_state_reserve_send", "chat_state_commit_outbox", "chat_state_mark_received",
		"dek_generate_and_wrap_dual", "generatekeypairwithrecoverywrap",
		"group_session_status", "getsessioncode",
		"mls_key_package_pool_sweep", "mls_commit_abandon",
		"getdevicekey", "savedevicekey",
	} {
		resp := app.HandleRequest([]byte(`{"action":"` + action + `","request_id":"old","payload":{}}`))
		if resp.Success || resp.ErrorCode != string(ErrCodeUnsupported) ||
			resp.Error != "unknown action: "+action || resp.RequestID != "old" {
			t.Errorf("%s: %+v", action, resp)
		}
	}
}

func TestHandleRequest_InvalidJSON(t *testing.T) {
	app := newFacadeTestApp()
	resp := app.HandleRequest([]byte(`{not valid json`))

	if resp.Success {
		t.Error("expected failure for invalid JSON")
	}
}

// 32B AES-GCM key Base64 (44 chars, 43 zero-byte 'A' + padding) — used
// to confirm the raw key decodes to 32B now that Validate is
// strengthened with requireBase64Len(key, 32).
const validDeviceKeyB64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

func TestHandleRequest_DeleteDeviceKey(t *testing.T) {
	app := newFacadeTestApp()
	if err := keychain.SaveDeviceKey(app.Store, validDeviceKeyB64); err != nil {
		t.Fatalf("setup: %v", err)
	}

	msg := `{"action":"deletedevicekey"}`
	resp := app.HandleRequest([]byte(msg))

	if !resp.Success {
		t.Errorf("delete device key failed: %s", resp.Error)
	}
}

func TestHandleRequest_DeviceKeyEnsureThenStatus(t *testing.T) {
	app := newFacadeTestApp()

	before := app.HandleRequest([]byte(`{"action":"device_key_status","request_id":"r1"}`))
	if !before.Success || before.RequestID != "r1" {
		t.Fatalf("status before ensure: %+v", before)
	}
	if before.Data.(DeviceKeyStatusResponseData).Present {
		t.Fatal("present before ensure")
	}

	ensured := app.HandleRequest([]byte(`{"action":"device_key_ensure"}`))
	if !ensured.Success || !ensured.Data.(DeviceKeyEnsureResponseData).Created {
		t.Fatalf("ensure: %+v", ensured)
	}
	after := app.HandleRequest([]byte(`{"action":"device_key_status"}`))
	if !after.Success || !after.Data.(DeviceKeyStatusResponseData).Present {
		t.Fatalf("status after ensure: %+v", after)
	}

	key, err := keychain.GetDeviceKey(app.Store)
	if err != nil {
		t.Fatalf("read stored key: %v", err)
	}
	for _, resp := range []BaseResponse{ensured, after} {
		encoded, _ := json.Marshal(resp)
		if key == "" || strings.Contains(string(encoded), key) || strings.Contains(string(encoded), `"key"`) {
			t.Fatalf("device key crossed the boundary: %s", encoded)
		}
	}
}

func TestHandleRequest_SignAlias_Flow(t *testing.T) {
	app := newFacadeTestApp()

	msg := `{"action":"signalias","payload":{"alias":"testuser"}}`
	resp := app.HandleRequest([]byte(msg))

	if !resp.Success {
		t.Fatalf("sign alias failed: %s", resp.Error)
	}

	data, _ := json.Marshal(resp.Data)
	var got SignAliasResponseData
	json.Unmarshal(data, &got)

	if got.Signature == "" {
		t.Error("signature should not be empty")
	}
	if got.PublicKey == "" {
		t.Error("public key should not be empty")
	}
	if got.WrappedKeeper != "" {
		t.Error("wrapped_keeper should be empty when wrap_key not provided")
	}
}

// When wrap_key_b64 is supplied, the Keeper must wrap the pending
// private key and include wrapped_keeper in the response.
func TestHandleRequest_SignAlias_WithRecoveryWrap(t *testing.T) {
	app := newFacadeTestApp()

	// Random 32B wrap key → Base64
	wrapKey := make([]byte, 32)
	for i := range wrapKey {
		wrapKey[i] = byte(i + 1)
	}
	wrapKeyB64 := base64.StdEncoding.EncodeToString(wrapKey)

	msg := fmt.Sprintf(
		`{"action":"signalias","payload":{"alias":"wrapuser","wrap_key_b64":%q}}`,
		wrapKeyB64,
	)
	resp := app.HandleRequest([]byte(msg))
	if !resp.Success {
		t.Fatalf("sign alias with wrap failed: %s", resp.Error)
	}

	data, _ := json.Marshal(resp.Data)
	var got SignAliasResponseData
	json.Unmarshal(data, &got)

	if got.Signature == "" || got.PublicKey == "" {
		t.Error("signature and publicKey should not be empty")
	}
	if got.WrappedKeeper == "" {
		t.Fatal("wrapped_keeper should not be empty when wrap_key provided")
	}

	// Verify wrap → unwrap roundtrip: decrypt via AESGCMDecryptBase64 and ensure a valid PEM comes out.
	decrypted, err := AESGCMDecryptBase64(wrapKey, got.WrappedKeeper)
	if err != nil {
		t.Fatalf("failed to decrypt wrapped_keeper: %v", err)
	}
	pemStr := string(decrypted)
	if !strings.Contains(pemStr, "PRIVATE KEY") {
		t.Errorf("decrypted wrapped_keeper does not look like a PEM private key: %q", pemStr)
	}

	// Confirm the wrapped value matches the actual pending private key.
	pending, err := keychain.GetPendingPrivateKey(app.Store)
	if err != nil {
		t.Fatalf("getPendingPrivateKey: %v", err)
	}
	if pemStr != pending {
		t.Error("decrypted wrapped_keeper does not match pending private key")
	}
}

func TestHandleRequest_SignAlias_WithInvalidWrapKeyLength(t *testing.T) {
	app := newFacadeTestApp()

	// 16 bytes (not 32)
	shortKey := base64.StdEncoding.EncodeToString(make([]byte, 16))
	msg := fmt.Sprintf(
		`{"action":"signalias","payload":{"alias":"bad","wrap_key_b64":%q}}`,
		shortKey,
	)
	resp := app.HandleRequest([]byte(msg))
	if resp.Success {
		t.Error("expected failure for 16-byte wrap_key")
	}
}

func TestHandleRequest_SignAlias_WithInvalidWrapKeyBase64(t *testing.T) {
	app := newFacadeTestApp()

	msg := `{"action":"signalias","payload":{"alias":"bad","wrap_key_b64":"!!!not-base64!!!"}}`
	resp := app.HandleRequest([]byte(msg))
	if resp.Success {
		t.Error("expected failure for invalid base64 wrap_key")
	}
}

func TestHandleRequest_SignAlias_AlreadyRegistered(t *testing.T) {
	// Set up permanent keypair + session code (simulates registered device)
	kp, _ := GenerateRSAKeyPair()
	app := newFacadeTestApp()
	keychain.SavePrivateKey(app.Store, kp.PrivateKey)
	keychain.SavePublicKey(app.Store, kp.PublicKey)
	keychain.SaveSessionCode(app.Store, "ABCD-EFGH-1234")

	msg := `{"action":"signalias","payload":{"alias":"testuser"}}`
	resp := app.HandleRequest([]byte(msg))

	if resp.Success {
		t.Error("expected failure when device already registered")
	}
}

func TestHandleRequest_SignAliasWithTimestamp(t *testing.T) {
	app := newFacadeTestApp()
	// Ensure permanent keypair exists
	kp, _ := GenerateRSAKeyPair()
	keychain.SavePrivateKey(app.Store, kp.PrivateKey)

	msg := `{"action":"signaliaswithtimestamp","payload":{"alias":"loginuser"}}`
	resp := app.HandleRequest([]byte(msg))

	if !resp.Success {
		t.Fatalf("sign alias with timestamp failed: %s", resp.Error)
	}

	data, _ := json.Marshal(resp.Data)
	var got SignAliasWithTimestampResponseData
	json.Unmarshal(data, &got)

	if got.Signature == "" {
		t.Error("signature should not be empty")
	}
	if got.Timestamp == 0 {
		t.Error("timestamp should not be zero")
	}
}

func TestHandleRequest_SignAliasWithTimestamp_NoKeypair(t *testing.T) {
	app := newFacadeTestApp()

	msg := `{"action":"signaliaswithtimestamp","payload":{"alias":"nokey"}}`
	resp := app.HandleRequest([]byte(msg))

	if resp.Success {
		t.Error("expected failure when no keypair exists")
	}
}

func TestHandleRequest_GetPublicKey(t *testing.T) {
	app := newFacadeTestApp()
	kp, _ := GenerateRSAKeyPair()
	keychain.SavePublicKey(app.Store, kp.PublicKey)

	msg := `{"action":"getpublickey"}`
	resp := app.HandleRequest([]byte(msg))

	if !resp.Success {
		t.Fatalf("get public key failed: %s", resp.Error)
	}

	data, _ := json.Marshal(resp.Data)
	var got GetPublicKeyResponseData
	json.Unmarshal(data, &got)

	if got.PublicKey != kp.PublicKey {
		t.Error("returned public key doesn't match saved key")
	}
}

func TestHandleRequest_GetServerPublicKey(t *testing.T) {
	app := newFacadeTestApp()
	// Ensure server public key is set
	if err := keychain.EnsureServerPublicKey(app.Store, app.Logger); err != nil {
		t.Fatalf("EnsureServerPublicKey: %v", err)
	}

	msg := `{"action":"getserverpubkey"}`
	resp := app.HandleRequest([]byte(msg))

	if !resp.Success {
		t.Fatalf("get server public key failed: %s", resp.Error)
	}

	data, _ := json.Marshal(resp.Data)
	var got GetServerPublicKeyResponseData
	json.Unmarshal(data, &got)

	if got.PublicKey == "" {
		t.Error("server public key should not be empty")
	}
}
