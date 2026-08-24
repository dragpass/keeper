// dek_aad.go — personal DEK direct AES-GCM encrypt handler with AAD binding.
//
// HandleDEKUnwrapAndEncryptWithAAD is the AAD-binding variant of
// HandleDEKUnwrapAndEncrypt (dek.go): it unwraps the device-wrapped personal
// DEK and seals plaintext under it, additionally binding a caller-supplied AAD
// into the GCM tag so the ciphertext is tied to its canonical context and
// cannot be swapped. The plaintext and the unwrapped DEK are zeroized; the
// response carries only {iv_b64, ciphertext_b64}. Plaintext / raw DEK appear
// zero times in the response and logs. The AAD is public context material.
//
// Personal-scope sibling of HandleGroupEncryptWithAAD — same AAD contract,
// different key source (device-wrapped personal DEK vs Group DEK handle).

package handlers

import (
	"encoding/base64"

	"github.com/awnumar/memguard"

	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/secure"
)

// HandleDEKUnwrapAndEncryptWithAAD unwraps the device-wrapped personal DEK and
// AES-GCM-seals the plaintext with the AAD bound into the tag.
func HandleDEKUnwrapAndEncryptWithAAD(
	d Deps, req proto.DEKUnwrapAndEncryptWithAADRequest,
) proto.BaseResponse {
	d.Logger.Println("dek unwrap and encrypt with aad request processing...")

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

	// AAD is public context material, not secret; no zeroize needed. Validate()
	// already confirmed it is non-empty valid Base64.
	aad, err := base64.StdEncoding.DecodeString(req.AADB64)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeValidation, "failed to decode aad_b64: "+err.Error())
	}

	dek, err := unwrapDeviceWrappedDEK(deviceKeyBuf.Bytes(), req.EncryptedDEKB64)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeCryptoFailure, err.Error())
	}
	defer secure.Zeroize(dek)

	iv, ciphertext, err := aesGCMSealSplitWithAAD(dek, plaintext, aad)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeCryptoFailure, "encrypt failed: "+err.Error())
	}
	if err := keychain.SavePersonalDeviceWrappedDEK(d.Store, req.EncryptedDEKB64); err != nil {
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "failed to save personal DEK: "+err.Error())
	}

	d.Logger.Println("dek unwrap and encrypt with aad successful")
	return proto.BaseResponse{Success: true, Data: proto.DEKUnwrapAndEncryptResponseData{
		IVB64:         base64.StdEncoding.EncodeToString(iv),
		CiphertextB64: base64.StdEncoding.EncodeToString(ciphertext),
	}}
}
