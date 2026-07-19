// dek.go — Personal DEK post-auth flow handlers (encrypt / rotate / password change).
//
//   - HandleDEKUnwrapAndEncrypt   : unwraps the device-wrapped DEK and AES-GCM-encrypts plaintext.
//   - HandleDEKRotateToDeviceKey  : login flow. password unwrap → rewrap with device.
//   - HandleDEKRotateToNewPassword: master password change.
//
// The signup-flow DEK generation/wrap (GenerateAndWrap{Dual,Password}) lives
// in dek_signup.go. PBKDF2 parameters + helpers
// (loadDeviceKeyFromKeychain / unwrapDeviceWrappedDEK) live in dek_helpers.go
// (shared with rotate_device_key.go).
//
// HandleDEKUnwrapAndDecrypt was removed. Replacement actions:
//   - dek_unwrap_and_decrypt_to_clipboard: writes plaintext directly to the Keeper-owned OS clipboard
//   - dek_unwrap_and_decrypt_meta: bulk-decrypts meta fields (UI-display carve-out)

package handlers

import (
	"crypto/sha256"
	"encoding/base64"

	"github.com/awnumar/memguard"
	"golang.org/x/crypto/pbkdf2"

	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/secure"
)

// HandleDEKUnwrapAndEncrypt unwraps the device-wrapped DEK and AES-GCM-encrypts the plaintext.
func HandleDEKUnwrapAndEncrypt(d Deps, req proto.DEKUnwrapAndEncryptRequest) proto.BaseResponse {
	d.Logger.Println("dek unwrap and encrypt request processing...")

	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}

	deviceKey, err := loadDeviceKeyFromKeychain(d.Store)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeStorageFailure, err.Error())
	}
	deviceKeyBuf := memguard.NewBufferFromBytes(deviceKey)
	defer deviceKeyBuf.Destroy()

	plaintext, err := base64.StdEncoding.DecodeString(req.PlaintextB64)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeValidation, "failed to decode plaintext_b64: "+err.Error())
	}
	defer secure.Zeroize(plaintext)

	dek, err := unwrapDeviceWrappedDEK(deviceKeyBuf.Bytes(), req.EncryptedDEKB64)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeCryptoFailure, err.Error())
	}
	defer secure.Zeroize(dek)

	iv, ciphertext, err := aesGCMSealSplit(dek, plaintext)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeCryptoFailure, "encrypt failed: "+err.Error())
	}

	d.Logger.Println("dek unwrap and encrypt successful")
	return proto.BaseResponse{Success: true, Data: proto.DEKUnwrapAndEncryptResponseData{
		IVB64:         base64.StdEncoding.EncodeToString(iv),
		CiphertextB64: base64.StdEncoding.EncodeToString(ciphertext),
	}}
}

// HandleDEKRotateToDeviceKey is the login flow's password→device rewrap.
func HandleDEKRotateToDeviceKey(d Deps, req proto.DEKRotateToDeviceKeyRequest) proto.BaseResponse {
	d.Logger.Println("dek rotate to device key request processing...")

	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}

	// protect password
	password := req.Password
	pwBuf := memguard.NewBufferFromBytes([]byte(password))
	secure.WipeString(&password)
	secure.WipeString(&req.Password)
	defer pwBuf.Destroy()
	return rotateDEKToDeviceKey(d, req.EncryptedDEKB64, pwBuf)
}

func rotateDEKToDeviceKey(d Deps, encryptedDEKB64 string, pwBuf *memguard.LockedBuffer) proto.BaseResponse {

	// fetch deviceKey internally — never accept it via the IPC payload
	deviceKey, err := loadDeviceKeyFromKeychain(d.Store)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeStorageFailure, err.Error())
	}
	deviceKeyBuf := memguard.NewBufferFromBytes(deviceKey)
	defer deviceKeyBuf.Destroy()

	// decode encrypted_dek: salt(16) || iv(12) || ciphertext_with_tag
	raw, err := base64.StdEncoding.DecodeString(encryptedDEKB64)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeValidation, "failed to decode encrypted_dek_b64: "+err.Error())
	}
	if len(raw) < dekSaltLength+12+16 { // salt + iv + min GCM tag
		return errs.CodeResponse(errs.ErrCodeValidation, "encrypted_dek too short")
	}
	salt := raw[:dekSaltLength]
	iv := raw[dekSaltLength : dekSaltLength+12]
	ciphertext := raw[dekSaltLength+12:]

	// derive KEK from password + decrypt DEK
	kek := pbkdf2.Key(pwBuf.Bytes(), salt, dekPBKDF2Iterations, dekKEKLength, sha256.New)
	defer secure.Zeroize(kek)

	dek, err := aesGCMOpen(kek, iv, ciphertext)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeCryptoFailure, "decrypt failed (wrong password?): "+err.Error())
	}
	defer secure.Zeroize(dek)
	if len(dek) != 32 {
		return errs.CodeResponse(errs.ErrCodeCryptoFailure, "unwrapped dek must be 32 bytes")
	}

	// rewrap with deviceKey
	devWrapped, err := aesGCMSeal(deviceKeyBuf.Bytes(), dek)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeCryptoFailure, "device wrap failed: "+err.Error())
	}

	d.Logger.Println("dek rotate to device key successful")
	return proto.BaseResponse{Success: true, Data: proto.DEKRotateToDeviceKeyResponseData{
		DeviceWrappedDEKB64: devWrapped,
	}}
}

// HandleDEKRotateToNewPassword — Master password change.
//
// device-wrapped DEK (raw Base64 decoded from deviceMaster) → unwrap with
// deviceKey → DEK → wrap with PBKDF2 of new password → returns new Base64
// for updating the server's `accounts.encrypted_dek`. deviceMaster itself is
// unchanged (deviceKey stays).
//
// Security: called only from Native Messaging. The caller (Extension
// background) confirms user intent before invoking. Old password verification
// happens at a separate surface (server-side password-wrap match comparison)
// — this handler only provides the mechanism.
func HandleDEKRotateToNewPassword(d Deps, req proto.DEKRotateToNewPasswordRequest) proto.BaseResponse {
	d.Logger.Println("dek rotate to new password request processing...")

	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}

	newPwd := req.NewPassword
	pwBuf := memguard.NewBufferFromBytes([]byte(newPwd))
	secure.WipeString(&newPwd)
	secure.WipeString(&req.NewPassword)
	defer pwBuf.Destroy()

	deviceKey, err := loadDeviceKeyFromKeychain(d.Store)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeStorageFailure, err.Error())
	}
	defer secure.Zeroize(deviceKey)

	dek, err := unwrapDeviceWrappedDEK(deviceKey, req.EncryptedDEKB64)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeCryptoFailure,
			"unwrap device-wrapped DEK failed: "+err.Error())
	}
	defer secure.Zeroize(dek)

	salt := make([]byte, dekSaltLength)
	if err := d.FillRandom(salt); err != nil {
		return errs.CodeResponse(errs.ErrCodeInternal, "failed to generate salt: "+err.Error())
	}
	kek := pbkdf2.Key(pwBuf.Bytes(), salt, dekPBKDF2Iterations, dekKEKLength, sha256.New)
	defer secure.Zeroize(kek)

	iv, ciphertext, err := aesGCMSealSplit(kek, dek)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeCryptoFailure, "wrap dek failed: "+err.Error())
	}

	// Same format as the server's `accounts.encrypted_dek`: salt(16) || iv(12) || ciphertext.
	out := make([]byte, 0, len(salt)+len(iv)+len(ciphertext))
	out = append(out, salt...)
	out = append(out, iv...)
	out = append(out, ciphertext...)

	d.Logger.Println("dek rotate to new password successful")
	return proto.BaseResponse{Success: true, Data: proto.DEKRotateToNewPasswordResponseData{
		EncryptedDEKB64: base64.StdEncoding.EncodeToString(out),
	}}
}
