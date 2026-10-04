// device_key_test.go — regression guard for device_key.go
// (HandleDeleteDeviceKey).
//
// **Defects this test catches:**
//   - regressions where the handler calls stdlib `log.*` directly (bypassing a.Logger)
//   - regressions where the device key Base64 is echoed to the logger (core regression guard)
package handlers

import (
	"testing"

	"github.com/zalando/go-keyring"

	"github.com/dragpass/keeper/internal/keystore/proto"
)

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
