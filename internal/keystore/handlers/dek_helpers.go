// dek_helpers.go — shared constants + helpers for personal DEK handlers.
//
//   - PBKDF2 parameters (compatible with Extension deriveKeyForWrapping).
//   - loadDeviceKeyFromKeychain — returns the OS Keychain device key as raw 32B.
//   - unwrapDeviceWrappedDEK — Base64(iv(12)||ct) → 32B plaintext DEK.
//
// rotate_device_key.go (voluntary DeviceKey rotation) uses the same helpers.

package handlers

import (
	"encoding/base64"
	"errors"

	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/secure"
)

// PBKDF2 parameters (compatible with Extension-side deriveKeyForWrapping)
//   - SHA-256, 600,000 iterations (OWASP 2025 recommendation), salt 16B, AES-256-GCM 32B key
const (
	DekPBKDF2Iterations = 600000
	DekSaltLength       = 16
	DekKEKLength        = 32

	// Other handler files in the same package reference these via lowercase names.
	dekPBKDF2Iterations = DekPBKDF2Iterations
	dekSaltLength       = DekSaltLength
	dekKEKLength        = DekKEKLength
)

// loadDeviceKeyFromKeychain decodes the OS Keychain DeviceKey and returns raw 32B.
// dek_* handlers never receive deviceKey via the IPC payload; they fetch it
// directly from the Keychain so the raw key never crosses the process boundary.
func loadDeviceKeyFromKeychain(store keychain.SecretStore) ([]byte, error) {
	deviceKeyB64, err := keychain.GetDeviceKey(store)
	if err != nil {
		return nil, errors.New("failed to read device key from keychain: " + err.Error())
	}
	if deviceKeyB64 == "" {
		return nil, errors.New("device key not found in keychain (signup required)")
	}
	raw, err := base64.StdEncoding.DecodeString(deviceKeyB64)
	if err != nil {
		return nil, errors.New("failed to decode device key from keychain: " + err.Error())
	}
	if len(raw) != 32 {
		secure.Zeroize(raw)
		return nil, errors.New("device key must be 32 bytes (AES-256 key)")
	}
	return raw, nil
}

// unwrapDeviceWrappedDEK unwraps Base64(iv(12)||ct) — decoded raw bytes from
// deviceMasterStorage — with the raw deviceKey and returns the 32B plaintext DEK.
func unwrapDeviceWrappedDEK(deviceKey []byte, encryptedDekB64 string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(encryptedDekB64)
	if err != nil {
		return nil, errors.New("failed to decode encrypted_dek_b64: " + err.Error())
	}
	if len(raw) < 12+32+16 { // iv + 32B DEK + GCM tag
		return nil, errors.New("encrypted_dek too short")
	}
	iv := raw[:12]
	ciphertext := raw[12:]
	dek, err := aesGCMOpen(deviceKey, iv, ciphertext)
	if err != nil {
		return nil, errors.New("dek decrypt failed: " + err.Error())
	}
	if len(dek) != 32 {
		secure.Zeroize(dek)
		return nil, errors.New("unwrapped dek must be 32 bytes")
	}
	return dek, nil
}

// deviceWrappedDEK returns the device-wrapped personal DEK a personal dek_*
// action opens: the one the caller sent, or when it sent none, the one this
// Keeper keeps in personal_device_wrapped_dek (written at login and signup,
// removed by device_signout). fromSlot tells the caller not to write the
// value back.
func deviceWrappedDEK(d Deps, supplied string) (wrapped string, fromSlot bool, resp proto.BaseResponse, ok bool) {
	if supplied != "" {
		return supplied, false, proto.BaseResponse{}, true
	}
	wrapped, err := keychain.GetPersonalDeviceWrappedDEK(d.Store)
	if errors.Is(err, keychain.ErrSecretNotFound) || (err == nil && wrapped == "") {
		return "", false, errs.CodeResponse(errs.ErrCodeNotFound, "personal DEK not found on this device"), false
	}
	if err != nil {
		d.Logger.Printf("personal DEK slot read failed: %v", err)
		return "", false, errs.CodeResponse(errs.ErrCodeStorageFailure, "failed to read personal DEK"), false
	}
	return wrapped, true, proto.BaseResponse{}, true
}
