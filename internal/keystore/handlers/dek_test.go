// dek_test.go — regression guard for the Personal DEK handlers in dek.go.
//
// All dek_* handlers fetch deviceKey from the SecretStore, so before calling
// a handler, tests seed the intended deviceKey into the store created by
// newTestDeps(t) via setKeychainDeviceKey. Earlier (when these tests lived in
// the keystore root) they used keyring.MockInit() + the global free function
// (saveDeviceKey); in this package they write directly to the
// MemorySecretStore bound to deps (instance isolation → safe in parallel).
package handlers

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/awnumar/memguard"
	"golang.org/x/crypto/pbkdf2"

	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// setKeychainDeviceKey seeds the deviceKey into the test's per-Deps SecretStore
// so that subsequent dek_* handler calls (which fetch from d.Store) see the
// expected key. "Different deviceKey scenario" tests re-call this just before
// the handler call to refresh the key.
func setKeychainDeviceKey(t *testing.T, store keychain.SecretStore, deviceKey []byte) {
	t.Helper()
	if err := keychain.SaveDeviceKey(store, base64.StdEncoding.EncodeToString(deviceKey)); err != nil {
		t.Fatalf("SaveDeviceKey: %v", err)
	}
}

// ────────────────────────────────────────────────────────────────────────
// generateAndWrapDual (the signup dual wrap)
//
// deviceKey is fetched directly from the Keychain instead of via IPC payload.
// Tests seed it with setKeychainDeviceKey before the call.
// ────────────────────────────────────────────────────────────────────────

// signupDEKForTest runs the signup dual wrap with the device copy saved as the
// active personal DEK, which is what the removed dek_generate_and_wrap_dual
// action did. Tests use it to seed a personal DEK.
func signupDEKForTest(d Deps, password string) proto.BaseResponse {
	pwBuf := memguard.NewBufferFromBytes([]byte(password))
	defer pwBuf.Destroy()
	data, resp := generateAndWrapDual(d, pwBuf, keychain.SavePersonalDeviceWrappedDEK)
	if !resp.Success {
		return resp
	}
	return proto.BaseResponse{Success: true, Data: data}
}

func TestGenerateAndWrapDual_BothWrapsRecoverSameDEK(t *testing.T) {
	deps, _, store := newTestDeps(t)
	deviceKey := make([]byte, 32)
	for i := range deviceKey {
		deviceKey[i] = byte(0x10 + i)
	}
	setKeychainDeviceKey(t, store, deviceKey)
	password := "testpass-dual"

	resp := signupDEKForTest(deps, password)
	if !resp.Success {
		t.Fatalf("dual wrap failed: %s", resp.Error)
	}
	data := resp.Data.(proto.DEKGenerateAndWrapDualResponseData)
	if data.PasswordWrappedDEKB64 == "" || data.DeviceWrappedDEKB64 == "" {
		t.Fatal("both wrap outputs should be present")
	}
	stored, err := keychain.GetPersonalDeviceWrappedDEK(store)
	if err != nil || stored != data.DeviceWrappedDEKB64 {
		t.Fatalf("stored personal DEK = %q, err = %v", stored, err)
	}

	pwRaw, err := base64.StdEncoding.DecodeString(data.PasswordWrappedDEKB64)
	if err != nil {
		t.Fatalf("decode pw: %v", err)
	}
	if len(pwRaw) < 16+12+32+16 {
		t.Fatalf("password wrap too short: %d", len(pwRaw))
	}
	salt := pwRaw[:16]
	pwIv := pwRaw[16 : 16+12]
	pwCt := pwRaw[16+12:]
	kek := pbkdf2.Key([]byte(password), salt, dekPBKDF2Iterations, dekKEKLength, sha256.New)
	dekFromPw, err := AESGCMOpen(kek, pwIv, pwCt)
	if err != nil {
		t.Fatalf("password decrypt: %v", err)
	}
	if len(dekFromPw) != 32 {
		t.Errorf("password-wrapped DEK length = %d, want 32", len(dekFromPw))
	}

	devRaw, err := base64.StdEncoding.DecodeString(data.DeviceWrappedDEKB64)
	if err != nil {
		t.Fatalf("decode dev: %v", err)
	}
	if len(devRaw) < 12+32+16 {
		t.Fatalf("device wrap too short: %d", len(devRaw))
	}
	devIv := devRaw[:12]
	devCt := devRaw[12:]
	dekFromDev, err := AESGCMOpen(deviceKey, devIv, devCt)
	if err != nil {
		t.Fatalf("device decrypt: %v", err)
	}

	if string(dekFromPw) != string(dekFromDev) {
		t.Error("password-wrapped and device-wrapped DEKs must decrypt to the same value")
	}
}

func TestGenerateAndWrapDual_DistinctOutputs(t *testing.T) {
	deps, _, store := newTestDeps(t)
	deviceKey := make([]byte, 32)
	setKeychainDeviceKey(t, store, deviceKey)

	r1 := signupDEKForTest(deps, "p")
	r2 := signupDEKForTest(deps, "p")
	d1 := r1.Data.(proto.DEKGenerateAndWrapDualResponseData)
	d2 := r2.Data.(proto.DEKGenerateAndWrapDualResponseData)

	if d1.PasswordWrappedDEKB64 == d2.PasswordWrappedDEKB64 {
		t.Error("password wraps should differ across calls")
	}
	if d1.DeviceWrappedDEKB64 == d2.DeviceWrappedDEKB64 {
		t.Error("device wraps should differ across calls")
	}
}

// TestGenerateAndWrapDual_NoKeychainDeviceKey: ensures the dual wrap clearly
// rejects when no deviceKey is present in the Store (security guard against
// running without a provisioned deviceKey).
func TestGenerateAndWrapDual_NoKeychainDeviceKey(t *testing.T) {
	deps, _, _ := newTestDeps(t) // empty store
	resp := signupDEKForTest(deps, "p")
	if resp.Success {
		t.Error("expected failure when device key not in keychain")
	}
	if !strings.Contains(resp.Error, "device key") {
		t.Errorf("error should mention device key, got: %q", resp.Error)
	}
}

// ────────────────────────────────────────────────────────────────────────
// dek_rotate_to_device_key
// ────────────────────────────────────────────────────────────────────────

// TestDEKRotateToDeviceKey_Roundtrip: feeds the password side of a dual-wrap
// result, rotates with a different deviceKey, and verifies both wraps refer
// to the same plaintext DEK.
func TestDEKRotateToDeviceKey_Roundtrip(t *testing.T) {
	deps, _, store := newTestDeps(t)
	deviceKey := make([]byte, 32)
	for i := range deviceKey {
		deviceKey[i] = byte(0x20 + i)
	}
	setKeychainDeviceKey(t, store, deviceKey)
	password := "testpass-rotate"

	signup := signupDEKForTest(deps, password)
	if !signup.Success {
		t.Fatalf("signup setup: %s", signup.Error)
	}
	signupData := signup.Data.(proto.DEKGenerateAndWrapDualResponseData)

	// simulate a new device — swap deviceKey in the store
	deviceKey2 := make([]byte, 32)
	for i := range deviceKey2 {
		deviceKey2[i] = byte(0xC0 + i)
	}
	setKeychainDeviceKey(t, store, deviceKey2)

	rotate := HandleDEKRotateToDeviceKey(deps, proto.DEKRotateToDeviceKeyRequest{
		Password:        password,
		EncryptedDEKB64: signupData.PasswordWrappedDEKB64,
	})
	if !rotate.Success {
		t.Fatalf("rotate failed: %s", rotate.Error)
	}
	rotateData := rotate.Data.(proto.DEKRotateToDeviceKeyResponseData)

	signupDevRaw, _ := base64.StdEncoding.DecodeString(signupData.DeviceWrappedDEKB64)
	signupDev, err := AESGCMOpen(deviceKey, signupDevRaw[:12], signupDevRaw[12:])
	if err != nil {
		t.Fatalf("signup device decrypt: %v", err)
	}

	rotateDevRaw, _ := base64.StdEncoding.DecodeString(rotateData.DeviceWrappedDEKB64)
	rotateDev, err := AESGCMOpen(deviceKey2, rotateDevRaw[:12], rotateDevRaw[12:])
	if err != nil {
		t.Fatalf("rotate device decrypt: %v", err)
	}

	if string(signupDev) != string(rotateDev) {
		t.Error("rotated DEK must equal original DEK")
	}
}

// passwordWrappedDEKFromOtherDevice returns the server's password-wrapped DEK
// as an account created on another device left it.
func passwordWrappedDEKFromOtherDevice(t *testing.T, password string) string {
	t.Helper()
	other, _, otherStore := newTestDeps(t)
	setKeychainDeviceKey(t, otherStore, make([]byte, 32))
	signup := signupDEKForTest(other, password)
	if !signup.Success {
		t.Fatalf("signup setup: %s", signup.Error)
	}
	return signup.Data.(proto.DEKGenerateAndWrapDualResponseData).PasswordWrappedDEKB64
}

// A device that got the account through an App recovery never ran signup, so
// it has no device key when the first password sign-in restores the DEK.
func TestDEKRotateToDeviceKey_CreatesDeviceKeyWhenAbsent(t *testing.T) {
	deps, _, store := newTestDeps(t)
	password := "testpass-recovered"
	wrapped := passwordWrappedDEKFromOtherDevice(t, password)

	rotate := HandleDEKRotateToDeviceKey(deps, proto.DEKRotateToDeviceKeyRequest{
		Password:        password,
		EncryptedDEKB64: wrapped,
	})
	if !rotate.Success {
		t.Fatalf("rotate failed: %s", rotate.Error)
	}
	deviceKeyB64, err := keychain.GetDeviceKey(store)
	if err != nil {
		t.Fatalf("device key not stored: %v", err)
	}
	deviceKey, err := base64.StdEncoding.DecodeString(deviceKeyB64)
	if err != nil || len(deviceKey) != 32 {
		t.Fatalf("stored device key is malformed: len=%d err=%v", len(deviceKey), err)
	}
	stored, err := keychain.GetPersonalDeviceWrappedDEK(store)
	if err != nil {
		t.Fatalf("personal DEK not stored: %v", err)
	}
	raw, _ := base64.StdEncoding.DecodeString(stored)
	if _, err := AESGCMOpen(deviceKey, raw[:12], raw[12:]); err != nil {
		t.Fatalf("stored DEK does not open with the created device key: %v", err)
	}
}

func TestDEKRotateToDeviceKey_WrongPasswordCreatesNoDeviceKey(t *testing.T) {
	deps, _, store := newTestDeps(t)
	wrapped := passwordWrappedDEKFromOtherDevice(t, "correct")

	rotate := HandleDEKRotateToDeviceKey(deps, proto.DEKRotateToDeviceKeyRequest{
		Password:        "WRONG",
		EncryptedDEKB64: wrapped,
	})
	if rotate.Success {
		t.Fatal("expected failure for wrong password")
	}
	present, err := keychain.DeviceKeyPresent(store)
	if err != nil || present {
		t.Fatalf("wrong password left a device key: present=%v err=%v", present, err)
	}
}

func TestDEKRotateToDeviceKey_WrongPasswordRejected(t *testing.T) {
	deps, _, store := newTestDeps(t)
	deviceKey := make([]byte, 32)
	setKeychainDeviceKey(t, store, deviceKey)

	signup := signupDEKForTest(deps, "correct")
	signupData := signup.Data.(proto.DEKGenerateAndWrapDualResponseData)

	rotate := HandleDEKRotateToDeviceKey(deps, proto.DEKRotateToDeviceKeyRequest{
		Password:        "WRONG",
		EncryptedDEKB64: signupData.PasswordWrappedDEKB64,
	})
	if rotate.Success {
		t.Error("expected failure for wrong password")
	}
}

func TestDEKRotateToDeviceKey_Validation(t *testing.T) {
	deps, _, store := newTestDeps(t)
	deviceKey := make([]byte, 32)
	setKeychainDeviceKey(t, store, deviceKey)

	cases := []proto.DEKRotateToDeviceKeyRequest{
		{Password: "", EncryptedDEKB64: "AA=="},
		{Password: "p", EncryptedDEKB64: ""},
	}
	for i, c := range cases {
		if resp := HandleDEKRotateToDeviceKey(deps, c); resp.Success {
			t.Errorf("case %d: expected validation failure", i)
		}
	}
}

func TestDEKRotateToDeviceKey_TooShortInput(t *testing.T) {
	deps, _, store := newTestDeps(t)
	deviceKey := make([]byte, 32)
	setKeychainDeviceKey(t, store, deviceKey)

	resp := HandleDEKRotateToDeviceKey(deps, proto.DEKRotateToDeviceKeyRequest{
		Password:        "p",
		EncryptedDEKB64: base64.StdEncoding.EncodeToString(make([]byte, 16)),
	})
	if resp.Success {
		t.Error("expected failure for too-short encrypted_dek_b64")
	}
}

// ────────────────────────────────────────────────────────────────────────
// dek_unwrap_and_encrypt / dek_unwrap_and_decrypt
// ────────────────────────────────────────────────────────────────────────

func signupAndGetDeviceWrap(t *testing.T, deps Deps, store keychain.SecretStore, password string, deviceKey []byte) string {
	t.Helper()
	setKeychainDeviceKey(t, store, deviceKey)
	resp := signupDEKForTest(deps, password)
	if !resp.Success {
		t.Fatalf("setup dual wrap: %s", resp.Error)
	}
	return resp.Data.(proto.DEKGenerateAndWrapDualResponseData).DeviceWrappedDEKB64
}

// The TestDEKUnwrapAndDecrypt_* series was removed along with
// HandleDEKUnwrapAndDecrypt. The roundtrip / tampered / keychain-key-changed
// / validation / bad-iv regression guards are covered by the unit tests for
// the clipboard sink action (HandleDEKUnwrapAndDecryptToClipboard).

func TestDEKUnwrap_EncryptValidation(t *testing.T) {
	deps, _, store := newTestDeps(t)
	deviceKey := make([]byte, 32)
	setKeychainDeviceKey(t, store, deviceKey)

	cases := []proto.DEKUnwrapAndEncryptRequest{
		{PlaintextB64: "AA=="},
		{EncryptedDEKB64: "AA=="},
	}
	for i, c := range cases {
		if resp := HandleDEKUnwrapAndEncrypt(deps, c); resp.Success {
			t.Errorf("case %d: expected validation failure", i)
		}
	}
}

// --- App receiver method DI guard --------
