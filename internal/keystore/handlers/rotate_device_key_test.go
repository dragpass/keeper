// rotate_device_key_test.go — regression guard for rotate_device_key.go
// (HandleRotateDeviceKey).
//
// **Defects this test catches:**
//   - regressions where the handler calls stdlib `log.*` directly (bypassing a.Logger)
//   - regressions where the validation-failure message echoes device_wrapped_dek_b64
//
// Production-ish round-trip tests migrated from the keystore root's
// rotate_device_key_facade_test.go are also merged into this file. Helper
// signatures were updated to use deps's SecretStore directly.
package handlers

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

func TestApp_HandleRotateDeviceKey_ValidationFailedLogged(t *testing.T) {
	deps, log, _ := newTestDeps(t)

	resp := HandleRotateDeviceKey(deps, proto.RotateDeviceKeyRequest{
		DeviceWrappedDEKB64: "", // empty → validation fail
	})

	if resp.Success {
		t.Fatalf("expected validation failure for empty input")
	}

	// the "processing..." log must appear, but success log must not.
	if !log.Contains("rotate_device_key request processing") {
		t.Fatalf("expected processing log")
	}
	if log.Contains("rotate_device_key successful") {
		t.Fatalf("must not log success on validation failure: %v", log.Messages())
	}
}

func TestApp_HandleRotateDeviceKey_DoesNotEchoInputInLogs(t *testing.T) {
	// Regression guard — whether the raw input echoes to the logger on the decode-failure branch.
	deps, log, _ := newTestDeps(t)

	const sentinel = "U1VQRVJfU0VDUkVUX1dSQVBQRURfRE9fTk9UX0xFQUs="
	resp := HandleRotateDeviceKey(deps, proto.RotateDeviceKeyRequest{
		DeviceWrappedDEKB64: sentinel,
	})
	// Whatever the outcome (requirement violations: too short / no Keychain key / etc.), it must fail.
	if resp.Success {
		t.Fatalf("expected failure with stub input")
	}

	if log.Contains(sentinel) {
		t.Fatalf("logger echoed input sentinel: %v", log.Messages())
	}
	if log.Contains("SUPER_SECRET") {
		t.Fatalf("logger echoed decoded sentinel: %v", log.Messages())
	}
}

// Free-function-delegation regressions are guarded by the keystore root's
// dispatcher_test.go via the JSON envelope path — the handlers-package unit
// tests directly call HandleRotateDeviceKey(deps, req), which is itself a
// free function call, so no extra guard is needed.

// ────────────────────────────────────────────────────────────────────────
// Production round-trip tests migrated from the keystore root's
// rotate_device_key_facade_test.go. Helpers were updated to use deps + store
// provided by newTestDeps(t) inside this package.
// ────────────────────────────────────────────────────────────────────────

// seedKeychainDeviceKeyForRotate seeds a 32B deviceKey filled with `fillByte`
// into the test's per-Deps SecretStore and returns the raw bytes.
//
// Almost identical to this package's setKeychainDeviceKey(t, store, key)
// helper, but kept for rotation-test scenarios where a fill-byte pattern +
// returning the raw bytes is more convenient.
func seedKeychainDeviceKeyForRotate(t *testing.T, store keychain.SecretStore, fillByte byte) []byte {
	t.Helper()
	dk := make([]byte, 32)
	for i := range dk {
		dk[i] = fillByte
	}
	if err := keychain.SaveDeviceKey(store, base64.StdEncoding.EncodeToString(dk)); err != nil {
		t.Fatalf("SaveDeviceKey: %v", err)
	}
	return dk
}

// rotateDualWrap simulates the dual-wrap flow that signup performs and returns
// the password-wrapped + device-wrapped Base64 strings. Tests can then exercise
// HandleRotateDeviceKey on the device-wrap value.
//
// Using the Keeper's dual-wrap result directly produces stable outputs even
// when a different deviceKey has been written to the keychain.
func rotateDualWrap(t *testing.T, deps Deps, store keychain.SecretStore, password string, deviceKey []byte) (passwordWrappedB64, deviceWrappedB64 string) {
	t.Helper()
	if err := keychain.SaveDeviceKey(store, base64.StdEncoding.EncodeToString(deviceKey)); err != nil {
		t.Fatalf("SaveDeviceKey: %v", err)
	}
	resp := HandleDEKGenerateAndWrapDual(deps, proto.DEKGenerateAndWrapDualRequest{Password: password})
	if !resp.Success {
		t.Fatalf("dual wrap setup failed: %s", resp.Error)
	}
	d := resp.Data.(proto.DEKGenerateAndWrapDualResponseData)
	return d.PasswordWrappedDEKB64, d.DeviceWrappedDEKB64
}

// TestRotateDeviceKey_Roundtrip: after rotation, the new wrap unwraps with
// the new deviceKey and the raw DEK is identical.
func TestRotateDeviceKey_Roundtrip(t *testing.T) {
	deps, _, store := newTestDeps(t)
	password := "rotate-pw"
	oldDK := seedKeychainDeviceKeyForRotate(t, store, 0x10)
	_, oldWrapB64 := rotateDualWrap(t, deps, store, password, oldDK)

	// Baseline consistency: oldWrap unwrapped with oldDK yields a 32B raw DEK
	oldWrapRaw, _ := base64.StdEncoding.DecodeString(oldWrapB64)
	originalDEK, err := aesGCMOpen(oldDK, oldWrapRaw[:12], oldWrapRaw[12:])
	if err != nil {
		t.Fatalf("baseline old wrap open failed: %v", err)
	}
	if len(originalDEK) != 32 {
		t.Fatalf("baseline raw DEK len %d, want 32", len(originalDEK))
	}

	// rotation call
	resp := HandleRotateDeviceKey(deps, proto.RotateDeviceKeyRequest{DeviceWrappedDEKB64: oldWrapB64})
	if !resp.Success {
		t.Fatalf("rotate_device_key failed: %s", resp.Error)
	}
	data := resp.Data.(proto.RotateDeviceKeyResponseData)
	if data.DeviceWrappedDEKB64 == "" {
		t.Fatal("response device_wrapped_dek_b64 should not be empty")
	}
	if data.DeviceWrappedDEKB64 == oldWrapB64 {
		t.Error("new wrap should differ from old wrap (new IV/key)")
	}

	// verify the keychain deviceKey was replaced with the new key
	stored, err := keychain.GetDeviceKey(store)
	if err != nil {
		t.Fatalf("GetDeviceKey after rotate: %v", err)
	}
	newDK, err := base64.StdEncoding.DecodeString(stored)
	if err != nil {
		t.Fatalf("decode new device key: %v", err)
	}
	if string(newDK) == string(oldDK) {
		t.Error("keychain device key should have been replaced")
	}

	// Unwrapping the new wrap with the new deviceKey must yield the same raw DEK
	newWrapRaw, _ := base64.StdEncoding.DecodeString(data.DeviceWrappedDEKB64)
	rotatedDEK, err := aesGCMOpen(newDK, newWrapRaw[:12], newWrapRaw[12:])
	if err != nil {
		t.Fatalf("new wrap open with new device key failed: %v", err)
	}
	if string(rotatedDEK) != string(originalDEK) {
		t.Error("raw DEK after rotation should equal raw DEK before rotation")
	}
}

// TestRotateDeviceKey_NewWrapNotDecryptableByOldKey: unwrapping the new wrap
// with the OLD deviceKey must fail GCM tag verification (deviceKey-separation guarantee).
func TestRotateDeviceKey_NewWrapNotDecryptableByOldKey(t *testing.T) {
	deps, _, store := newTestDeps(t)
	oldDK := seedKeychainDeviceKeyForRotate(t, store, 0x20)
	_, oldWrapB64 := rotateDualWrap(t, deps, store, "p", oldDK)

	resp := HandleRotateDeviceKey(deps, proto.RotateDeviceKeyRequest{DeviceWrappedDEKB64: oldWrapB64})
	if !resp.Success {
		t.Fatalf("rotate failed: %s", resp.Error)
	}
	data := resp.Data.(proto.RotateDeviceKeyResponseData)
	newWrapRaw, _ := base64.StdEncoding.DecodeString(data.DeviceWrappedDEKB64)

	// attempting to unwrap the new wrap with OLD deviceKey must fail
	if _, err := aesGCMOpen(oldDK, newWrapRaw[:12], newWrapRaw[12:]); err == nil {
		t.Error("new wrap should not decrypt with old device key")
	}
}

// TestRotateDeviceKey_OldWrapStillDecryptableByNewKey_ShouldFail:
// attempting to unwrap the OLD wrap with the new deviceKey must fail.
// (After rotation the existing wrap is meaningless until deviceMasterStorage is refreshed.)
func TestRotateDeviceKey_OldWrapNotDecryptableByNewKey(t *testing.T) {
	deps, _, store := newTestDeps(t)
	oldDK := seedKeychainDeviceKeyForRotate(t, store, 0x30)
	_, oldWrapB64 := rotateDualWrap(t, deps, store, "p", oldDK)

	resp := HandleRotateDeviceKey(deps, proto.RotateDeviceKeyRequest{DeviceWrappedDEKB64: oldWrapB64})
	if !resp.Success {
		t.Fatalf("rotate failed: %s", resp.Error)
	}

	// fetch the new deviceKey
	stored, _ := keychain.GetDeviceKey(store)
	newDK, _ := base64.StdEncoding.DecodeString(stored)

	oldWrapRaw, _ := base64.StdEncoding.DecodeString(oldWrapB64)
	if _, err := aesGCMOpen(newDK, oldWrapRaw[:12], oldWrapRaw[12:]); err == nil {
		t.Error("old wrap should NOT decrypt with new device key")
	}
}

// TestRotateDeviceKey_NoKeychainDeviceKey: clearly reject when the keychain has no deviceKey.
func TestRotateDeviceKey_NoKeychainDeviceKey(t *testing.T) {
	deps, _, store := newTestDeps(t)
	_ = keychain.DeleteDeviceKey(store)
	resp := HandleRotateDeviceKey(deps, proto.RotateDeviceKeyRequest{DeviceWrappedDEKB64: base64.StdEncoding.EncodeToString(make([]byte, 60))})
	if resp.Success {
		t.Error("expected failure when device key absent")
	}
	if !strings.Contains(resp.Error, "device key") {
		t.Errorf("error should mention device key, got: %q", resp.Error)
	}
}

// TestRotateDeviceKey_TooShortInput: reject too-short wrap.
func TestRotateDeviceKey_TooShortInput(t *testing.T) {
	deps, _, store := newTestDeps(t)
	seedKeychainDeviceKeyForRotate(t, store, 0x40)
	resp := HandleRotateDeviceKey(deps, proto.RotateDeviceKeyRequest{DeviceWrappedDEKB64: base64.StdEncoding.EncodeToString(make([]byte, 16))})
	if resp.Success {
		t.Error("expected failure for too-short wrap input")
	}
}

// TestRotateDeviceKey_InvalidWrap_KeychainUntouched: when unwrap fails, the
// deviceKey remaining in the keychain must not change.
func TestRotateDeviceKey_InvalidWrap_KeychainUntouched(t *testing.T) {
	deps, _, store := newTestDeps(t)
	oldDK := seedKeychainDeviceKeyForRotate(t, store, 0x50)

	// Send 60 random bytes (iv 12 + ct 48) pretending to be a wrap → unwrap fails
	bogus := make([]byte, 60)
	for i := range bogus {
		bogus[i] = byte(i)
	}
	resp := HandleRotateDeviceKey(deps, proto.RotateDeviceKeyRequest{
		DeviceWrappedDEKB64: base64.StdEncoding.EncodeToString(bogus),
	})
	if resp.Success {
		t.Error("expected failure for invalid wrap")
	}

	// keychain still holds oldDK
	stored, err := keychain.GetDeviceKey(store)
	if err != nil {
		t.Fatalf("GetDeviceKey: %v", err)
	}
	storedRaw, _ := base64.StdEncoding.DecodeString(stored)
	if string(storedRaw) != string(oldDK) {
		t.Error("keychain device key should remain unchanged on unwrap failure")
	}
}

// TestRotateDeviceKey_Validation: reject empty input.
func TestRotateDeviceKey_Validation(t *testing.T) {
	deps, _, store := newTestDeps(t)
	seedKeychainDeviceKeyForRotate(t, store, 0x60)
	if resp := HandleRotateDeviceKey(deps, proto.RotateDeviceKeyRequest{DeviceWrappedDEKB64: ""}); resp.Success {
		t.Error("expected failure for empty input")
	}
}

// TestRotateDeviceKey_PostRotateLoginPathContinuity: after rotation, the
// password branch of the dual wrap (server's encrypted_dek) is unaffected —
// DEKRotateToDeviceKey unwrapping with password and rewrapping with the NEW
// deviceKey must yield the same raw DEK.
//
// Scenario:
//  1. signup: dualWrap(pw, oldDK) → server holds password wrap, local holds device wrap
//  2. deviceKey rotation → new deviceKey, new device wrap
//  3. (simulating login on another device) DEKRotateToDeviceKey(pw, server's password wrap)
//     → rewrap with new deviceKey, raw DEK is the same
func TestRotateDeviceKey_PostRotateLoginPathContinuity(t *testing.T) {
	deps, _, store := newTestDeps(t)
	password := "continuity-pw"
	oldDK := seedKeychainDeviceKeyForRotate(t, store, 0x70)
	pwWrapB64, oldDeviceWrapB64 := rotateDualWrap(t, deps, store, password, oldDK)

	// extract raw DEK (baseline for comparison)
	oldWrapRaw, _ := base64.StdEncoding.DecodeString(oldDeviceWrapB64)
	originalDEK, err := aesGCMOpen(oldDK, oldWrapRaw[:12], oldWrapRaw[12:])
	if err != nil {
		t.Fatalf("baseline open failed: %v", err)
	}

	// perform rotation
	rotResp := HandleRotateDeviceKey(deps, proto.RotateDeviceKeyRequest{DeviceWrappedDEKB64: oldDeviceWrapB64})
	if !rotResp.Success {
		t.Fatalf("rotate: %s", rotResp.Error)
	}

	// Use keychain's new deviceKey to flow password wrap → NEW device wrap (login path)
	loginResp := HandleDEKRotateToDeviceKey(deps, proto.DEKRotateToDeviceKeyRequest{
		Password:        password,
		EncryptedDEKB64: pwWrapB64,
	})
	if !loginResp.Success {
		t.Fatalf("login-path rotate: %s", loginResp.Error)
	}
	loginData := loginResp.Data.(proto.DEKRotateToDeviceKeyResponseData)
	loginWrapRaw, _ := base64.StdEncoding.DecodeString(loginData.DeviceWrappedDEKB64)

	stored, _ := keychain.GetDeviceKey(store)
	newDK, _ := base64.StdEncoding.DecodeString(stored)
	loginRotatedDEK, err := aesGCMOpen(newDK, loginWrapRaw[:12], loginWrapRaw[12:])
	if err != nil {
		t.Fatalf("login-path open failed: %v", err)
	}
	if string(loginRotatedDEK) != string(originalDEK) {
		t.Error("after device key rotation, password-wrapped DEK should still resolve to the original raw DEK")
	}
}
