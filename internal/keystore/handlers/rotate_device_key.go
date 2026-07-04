// rotate_device_key.go — voluntary DeviceKey rotation composite action.

package handlers

import (
	"encoding/base64"
	"errors"

	"github.com/awnumar/memguard"

	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/secure"
)

// HandleRotateDeviceKey is the voluntary DeviceKey rotation composite action.
//
// Steps:
//  1. decode input device-wrapped DEK (iv(12) || ciphertext(>=32+16))
//  2. fetch OLD deviceKey from the Keychain (memguard)
//  3. unwrap with OLD deviceKey → raw 32B personal DEK (memguard)
//  4. generate new 32B deviceKey (memguard)
//  5. AES-GCM wrap raw DEK with the new deviceKey → new wrap bytes
//  6. save the new deviceKey to the Keychain (saveDeviceKey overwrites OLD)
//  7. zeroize all plaintext buffers, return the response
func HandleRotateDeviceKey(d Deps, req proto.RotateDeviceKeyRequest) proto.BaseResponse {
	d.Logger.Println("rotate_device_key request processing...")

	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}

	// 1) decode input
	rawWrapped, err := base64.StdEncoding.DecodeString(req.DeviceWrappedDEKB64)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeValidation, "failed to decode device_wrapped_dek_b64: "+err.Error())
	}
	if len(rawWrapped) < 12+32+16 { // iv + 32B DEK + GCM tag
		return errs.CodeResponse(errs.ErrCodeValidation, "device_wrapped_dek_b64 too short")
	}

	// 2) fetch OLD deviceKey
	oldDeviceKey, err := loadDeviceKeyFromKeychain(d.Store)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeStorageFailure, err.Error())
	}
	oldBuf := memguard.NewBufferFromBytes(oldDeviceKey)
	defer oldBuf.Destroy()

	// 3) unwrap with OLD
	dek, err := unwrapDeviceWrappedDEK(oldBuf.Bytes(), req.DeviceWrappedDEKB64)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeCryptoFailure, "unwrap with old device key failed: "+err.Error())
	}
	defer secure.Zeroize(dek)
	if len(dek) != 32 {
		return errs.CodeResponse(errs.ErrCodeCryptoFailure, "unwrapped dek must be 32 bytes")
	}

	// 4) generate new 32B deviceKey
	newDeviceKey := make([]byte, 32)
	if err := d.FillRandom(newDeviceKey); err != nil {
		return errs.CodeResponse(errs.ErrCodeInternal, "failed to generate new device key: "+err.Error())
	}
	newBuf := memguard.NewBufferFromBytes(newDeviceKey)
	defer newBuf.Destroy()

	// 5) wrap with new deviceKey
	newWrappedB64, err := aesGCMSeal(newBuf.Bytes(), dek)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeCryptoFailure, "wrap with new device key failed: "+err.Error())
	}

	// Sanity: the new wrap must not be unwrappable with OLD.
	if _, oldOpenErr := unwrapDeviceWrappedDEK(oldBuf.Bytes(), newWrappedB64); oldOpenErr == nil {
		return errs.CodeResponse(errs.ErrCodeInternal, errors.New("internal: new wrap unexpectedly opens with old device key").Error())
	}

	// 6) save to Keychain (overwrite OLD)
	if err := keychain.SaveDeviceKey(d.Store, base64.StdEncoding.EncodeToString(newBuf.Bytes())); err != nil {
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "failed to save new device key to keychain: "+err.Error())
	}

	d.Logger.Println("rotate_device_key successful")
	return proto.BaseResponse{Success: true, Data: proto.RotateDeviceKeyResponseData{
		DeviceWrappedDEKB64: newWrappedB64,
	}}
}
