// device_key_test.go — regression guard for device_key.go (HandleSaveDeviceKey /
// HandleGetDeviceKey / HandleDeleteDeviceKey).
//
// **Defects this test catches:**
//   - regressions where the handler calls stdlib `log.*` directly (bypassing a.Logger)
//   - regressions where the device key Base64 is echoed to the logger (core regression guard)
package handlers

import (
	"testing"

	"github.com/zalando/go-keyring"

	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// TestApp_HandleSaveDeviceKey_DoesNotEchoKey: ensures the device key Base64
// input is not echoed to the log. saveDeviceKey itself succeeds with an empty
// keychain.
func TestApp_HandleSaveDeviceKey_DoesNotEchoKey(t *testing.T) {
	keyring.MockInit()
	deps, log, _ := newTestDeps(t)

	const deviceKeySentinel = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	resp := HandleSaveDeviceKey(deps, proto.SaveDeviceKeyRequest{Key: deviceKeySentinel})
	if !resp.Success {
		t.Fatalf("save should succeed on mock keychain, got %s", resp.Error)
	}
	if !log.Contains("key save request processing") {
		t.Fatalf("expected processing log")
	}
	if log.Contains(deviceKeySentinel) {
		t.Fatalf("logger leaked device key: %v", log.Messages())
	}
}

// TestApp_HandleGetDeviceKey_LogsLifecycle_AfterSave: ensures the save → get
// round trip goes through the logger and the key value is not echoed to it.
func TestApp_HandleGetDeviceKey_LogsLifecycle_AfterSave(t *testing.T) {
	keyring.MockInit()
	deps, log, store := newTestDeps(t)

	const sentinel = "DEVICE_KEY_BASE64_VALUE_DO_NOT_LEAK"
	if err := keychain.SaveDeviceKey(store, sentinel); err != nil {
		t.Fatalf("test setup: SaveDeviceKey: %v", err)
	}

	resp := HandleGetDeviceKey(deps, proto.GetDeviceKeyRequest{})
	if !resp.Success {
		t.Fatalf("get should succeed after save: %s", resp.Error)
	}
	if !log.Contains("key retrieval request processing") {
		t.Fatalf("expected processing log")
	}
	// The response payload includes the key, but the logger must not.
	if log.Contains(sentinel) {
		t.Fatalf("logger leaked device key: %v", log.Messages())
	}
}

func TestApp_HandleDeleteDeviceKey_LogsProcessing(t *testing.T) {
	keyring.MockInit()
	deps, log, _ := newTestDeps(t)

	// Delete from an empty keychain — regardless of whether the implementation
	// treats not-found as success or error, the processing log must be emitted.
	resp := HandleDeleteDeviceKey(deps, proto.DeleteDeviceKeyRequest{})
	_ = resp
	if !log.Contains("key delete request processing") {
		t.Fatalf("expected processing log, got %v", log.Messages())
	}
}
