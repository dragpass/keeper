// dek_test.go — regression guard for the Personal DEK handlers in dek.go.
//
// All dek_* handlers fetch deviceKey from the SecretStore, so before calling
// a handler, tests seed the intended deviceKey into the store created by
// newTestDeps(t) via setKeychainDeviceKey. Earlier (when these tests lived in
// the keystore root) they used keyring.MockInit() + the global free function
// (saveDeviceKey); in this package they write directly to the
// MemorySecretStore bound to deps (instance isolation → safe in parallel).
//
// **Additional defects caught:**
//   - regressions where HandleDEKGenerateAndWrapPassword's input password is
//     echoed to the logger (core security regression guard)
package handlers

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"

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

// TestDEKGenerateAndWrapPassword_FormatAndDecrypt: ensures the output
// EncryptedDEKB64 is in salt(16) || iv(12) || ciphertext_with_tag format and
// decrypting with the same password + extracted salt yields a 32B raw DEK.
// Same convention as the Extension's deriveKeyForWrapping (PBKDF2-SHA256,
// 600,000 iters, AES-256-GCM).
func TestDEKGenerateAndWrapPassword_FormatAndDecrypt(t *testing.T) {
	deps, _, _ := newTestDeps(t)
	password := "testpass-12345"
	resp := HandleDEKGenerateAndWrapPassword(deps, proto.DEKGenerateAndWrapPasswordRequest{
		Password: password,
	})
	if !resp.Success {
		t.Fatalf("dek generate failed: %s", resp.Error)
	}
	data := resp.Data.(proto.DEKGenerateAndWrapPasswordResponseData)
	if data.EncryptedDEKB64 == "" {
		t.Fatal("encrypted_dek_b64 should not be empty")
	}

	raw, err := base64.StdEncoding.DecodeString(data.EncryptedDEKB64)
	if err != nil {
		t.Fatalf("decode b64: %v", err)
	}
	if len(raw) < 16+12+32+16 {
		t.Fatalf("output too short: %d", len(raw))
	}

	salt := raw[:16]
	iv := raw[16 : 16+12]
	ciphertext := raw[16+12:]

	kek := pbkdf2.Key([]byte(password), salt, dekPBKDF2Iterations, dekKEKLength, sha256.New)
	plaintext, err := AESGCMOpen(kek, iv, ciphertext)
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}
	if len(plaintext) != 32 {
		t.Errorf("dek length = %d, want 32", len(plaintext))
	}
}

// TestDEKGenerateAndWrapPassword_WrongPasswordRejected: ensures the GCM tag
// check fails when decrypting with a different password (basis of the
// zero-knowledge guarantee).
func TestDEKGenerateAndWrapPassword_WrongPasswordRejected(t *testing.T) {
	deps, _, _ := newTestDeps(t)
	resp := HandleDEKGenerateAndWrapPassword(deps, proto.DEKGenerateAndWrapPasswordRequest{
		Password: "correct-password",
	})
	if !resp.Success {
		t.Fatalf("setup: %s", resp.Error)
	}
	data := resp.Data.(proto.DEKGenerateAndWrapPasswordResponseData)
	raw, _ := base64.StdEncoding.DecodeString(data.EncryptedDEKB64)
	salt, iv, ciphertext := raw[:16], raw[16:28], raw[28:]

	wrongKEK := pbkdf2.Key([]byte("WRONG-password"), salt, dekPBKDF2Iterations, dekKEKLength, sha256.New)
	if _, err := AESGCMOpen(wrongKEK, iv, ciphertext); err == nil {
		t.Error("decrypt should fail with wrong password")
	}
}

// TestDEKGenerateAndWrapPassword_DistinctOutputs: calling twice with the same
// password must produce different salt/IV/DEK each time (no determinism).
func TestDEKGenerateAndWrapPassword_DistinctOutputs(t *testing.T) {
	deps, _, _ := newTestDeps(t)
	password := "samepass"
	r1 := HandleDEKGenerateAndWrapPassword(deps, proto.DEKGenerateAndWrapPasswordRequest{Password: password})
	r2 := HandleDEKGenerateAndWrapPassword(deps, proto.DEKGenerateAndWrapPasswordRequest{Password: password})

	o1 := r1.Data.(proto.DEKGenerateAndWrapPasswordResponseData).EncryptedDEKB64
	o2 := r2.Data.(proto.DEKGenerateAndWrapPasswordResponseData).EncryptedDEKB64
	if o1 == o2 {
		t.Error("two calls with same password should produce distinct outputs (different salt/iv/dek)")
	}
	if !strings.HasPrefix(o1, "") {
		t.Fatal("unreachable")
	}
}

func TestDEKGenerateAndWrapPassword_EmptyRejected(t *testing.T) {
	deps, _, _ := newTestDeps(t)
	resp := HandleDEKGenerateAndWrapPassword(deps, proto.DEKGenerateAndWrapPasswordRequest{Password: ""})
	if resp.Success {
		t.Error("expected failure for empty password")
	}
}

// ────────────────────────────────────────────────────────────────────────
// dek_generate_and_wrap_dual
//
// deviceKey is fetched directly from the Keychain instead of via IPC payload.
// Tests seed it with setKeychainDeviceKey before the call.
// ────────────────────────────────────────────────────────────────────────

func TestDEKGenerateAndWrapDual_BothWrapsRecoverSameDEK(t *testing.T) {
	deps, _, store := newTestDeps(t)
	deviceKey := make([]byte, 32)
	for i := range deviceKey {
		deviceKey[i] = byte(0x10 + i)
	}
	setKeychainDeviceKey(t, store, deviceKey)
	password := "testpass-dual"

	resp := HandleDEKGenerateAndWrapDual(deps, proto.DEKGenerateAndWrapDualRequest{Password: password})
	if !resp.Success {
		t.Fatalf("dual wrap failed: %s", resp.Error)
	}
	data := resp.Data.(proto.DEKGenerateAndWrapDualResponseData)
	if data.PasswordWrappedDEKB64 == "" || data.DeviceWrappedDEKB64 == "" {
		t.Fatal("both wrap outputs should be present")
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

func TestDEKGenerateAndWrapDual_DistinctOutputs(t *testing.T) {
	deps, _, store := newTestDeps(t)
	deviceKey := make([]byte, 32)
	setKeychainDeviceKey(t, store, deviceKey)

	r1 := HandleDEKGenerateAndWrapDual(deps, proto.DEKGenerateAndWrapDualRequest{Password: "p"})
	r2 := HandleDEKGenerateAndWrapDual(deps, proto.DEKGenerateAndWrapDualRequest{Password: "p"})
	d1 := r1.Data.(proto.DEKGenerateAndWrapDualResponseData)
	d2 := r2.Data.(proto.DEKGenerateAndWrapDualResponseData)

	if d1.PasswordWrappedDEKB64 == d2.PasswordWrappedDEKB64 {
		t.Error("password wraps should differ across calls")
	}
	if d1.DeviceWrappedDEKB64 == d2.DeviceWrappedDEKB64 {
		t.Error("device wraps should differ across calls")
	}
}

// TestDEKGenerateAndWrapDual_NoKeychainDeviceKey: ensures the handler clearly
// rejects when no deviceKey is present in the Store (security guard against
// running without a provisioned deviceKey).
func TestDEKGenerateAndWrapDual_NoKeychainDeviceKey(t *testing.T) {
	deps, _, _ := newTestDeps(t) // empty store
	resp := HandleDEKGenerateAndWrapDual(deps, proto.DEKGenerateAndWrapDualRequest{Password: "p"})
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

	signup := HandleDEKGenerateAndWrapDual(deps, proto.DEKGenerateAndWrapDualRequest{Password: password})
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

func TestDEKRotateToDeviceKey_WrongPasswordRejected(t *testing.T) {
	deps, _, store := newTestDeps(t)
	deviceKey := make([]byte, 32)
	setKeychainDeviceKey(t, store, deviceKey)

	signup := HandleDEKGenerateAndWrapDual(deps, proto.DEKGenerateAndWrapDualRequest{Password: "correct"})
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
	resp := HandleDEKGenerateAndWrapDual(deps, proto.DEKGenerateAndWrapDualRequest{Password: password})
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

// TestDEKGenerateAndWrapDual_Validation: ensures an empty password is rejected.
func TestDEKGenerateAndWrapDual_Validation(t *testing.T) {
	deps, _, store := newTestDeps(t)
	deviceKey := make([]byte, 32)
	setKeychainDeviceKey(t, store, deviceKey)

	t.Run("empty_password", func(t *testing.T) {
		resp := HandleDEKGenerateAndWrapDual(deps, proto.DEKGenerateAndWrapDualRequest{Password: ""})
		if resp.Success {
			t.Error("expected failure")
		}
	})
}

// --- App receiver method DI guard --------

func TestApp_HandleDEKGenerateAndWrapPassword_LogsLifecycle(t *testing.T) {
	deps, log, _ := newTestDeps(t)

	resp := HandleDEKGenerateAndWrapPassword(deps, proto.DEKGenerateAndWrapPasswordRequest{Password: "pw"})
	if !resp.Success {
		t.Fatalf("password wrap should succeed: %s", resp.Error)
	}
	if !log.Contains("dek generate and wrap password request processing") {
		t.Fatalf("expected processing log")
	}
	if !log.Contains("dek generate and wrap password successful") {
		t.Fatalf("expected success log")
	}
}

func TestApp_HandleDEKGenerateAndWrapPassword_DoesNotEchoPassword(t *testing.T) {
	deps, log, _ := newTestDeps(t)

	const sentinel = "SUPER_SECRET_USER_PASSWORD_DO_NOT_LEAK"
	resp := HandleDEKGenerateAndWrapPassword(deps, proto.DEKGenerateAndWrapPasswordRequest{Password: sentinel})
	if !resp.Success {
		t.Fatalf("password wrap should succeed: %s", resp.Error)
	}
	if log.Contains(sentinel) {
		t.Fatalf("logger leaked password: %v", log.Messages())
	}
}
