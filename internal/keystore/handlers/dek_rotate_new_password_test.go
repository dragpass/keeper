// dek_rotate_new_password_test.go — regression guard for
// HandleDEKRotateToNewPassword (master password change) in dek.go.
//
// The handler unwraps the device-wrapped DEK with the Keychain deviceKey and
// rewraps it under a PBKDF2 KEK derived from the new password, returning the
// server `accounts.encrypted_dek` format salt(16) || iv(12) || ciphertext.
package handlers

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"golang.org/x/crypto/pbkdf2"

	"github.com/dragpass/keeper/internal/keystore/proto"
)

// TestDEKRotateToNewPassword_Roundtrip: rewrapping the device-wrapped DEK
// under a new password yields output that decrypts (with the new password +
// embedded salt/iv) back to the exact original DEK.
func TestDEKRotateToNewPassword_Roundtrip(t *testing.T) {
	deps, _, store := newTestDeps(t)
	deviceKey := make([]byte, 32)
	for i := range deviceKey {
		deviceKey[i] = byte(0x30 + i)
	}
	deviceWrapped := signupAndGetDeviceWrap(t, deps, store, "old-master-pass", deviceKey)

	// original DEK = unwrap the device-wrapped bytes (iv(12) || ciphertext).
	devRaw, err := base64.StdEncoding.DecodeString(deviceWrapped)
	if err != nil {
		t.Fatalf("decode device-wrapped: %v", err)
	}
	origDEK, err := AESGCMOpen(deviceKey, devRaw[:12], devRaw[12:])
	if err != nil {
		t.Fatalf("unwrap device DEK: %v", err)
	}

	const newPassword = "brand-new-master-pass"
	resp := HandleDEKRotateToNewPassword(deps, proto.DEKRotateToNewPasswordRequest{
		EncryptedDEKB64: deviceWrapped,
		NewPassword:     newPassword,
	})
	if !resp.Success {
		t.Fatalf("rotate to new password failed: %s", resp.Error)
	}
	data := resp.Data.(proto.DEKRotateToNewPasswordResponseData)
	if data.EncryptedDEKB64 == "" {
		t.Fatal("encrypted_dek_b64 should not be empty")
	}

	// output = salt(16) || iv(12) || ciphertext; decrypt with the new password.
	out, err := base64.StdEncoding.DecodeString(data.EncryptedDEKB64)
	if err != nil {
		t.Fatalf("decode output: %v", err)
	}
	if len(out) < dekSaltLength+12 {
		t.Fatalf("output too short: %d bytes", len(out))
	}
	salt := out[:dekSaltLength]
	iv := out[dekSaltLength : dekSaltLength+12]
	ct := out[dekSaltLength+12:]
	kek := pbkdf2.Key([]byte(newPassword), salt, dekPBKDF2Iterations, dekKEKLength, sha256.New)
	got, err := AESGCMOpen(kek, iv, ct)
	if err != nil {
		t.Fatalf("decrypt with new password: %v", err)
	}
	if string(got) != string(origDEK) {
		t.Error("rewrapped DEK must equal the original DEK")
	}
}

// TestDEKRotateToNewPassword_DoesNotEchoPassword: the new password must never
// reach the logger.
func TestDEKRotateToNewPassword_DoesNotEchoPassword(t *testing.T) {
	deps, log, store := newTestDeps(t)
	deviceKey := make([]byte, 32)
	deviceWrapped := signupAndGetDeviceWrap(t, deps, store, "old-master-pass", deviceKey)

	const sentinel = "SUPER_SECRET_NEW_PASSWORD_DO_NOT_LEAK"
	resp := HandleDEKRotateToNewPassword(deps, proto.DEKRotateToNewPasswordRequest{
		EncryptedDEKB64: deviceWrapped,
		NewPassword:     sentinel,
	})
	if !resp.Success {
		t.Fatalf("rotate should succeed: %s", resp.Error)
	}
	if log.Contains(sentinel) {
		t.Fatalf("logger leaked new password: %v", log.Messages())
	}
}
