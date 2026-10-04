// device_key.go — DeviceKey handlers. Manages the 32B AES-GCM deviceKey in
// the OS Keychain. HandleDeviceKeyStatus / HandleDeviceKeyEnsure keep the key
// inside Keeper; HandleGetDeviceKey / HandleSaveDeviceKey move it across the
// IPC boundary and remain only for extensions that predate the other two.

package handlers

import (
	"encoding/base64"
	"errors"

	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/secure"
)

// HandleGetDeviceKey handles device key retrieval requests.
//
// Deprecated: returns the raw deviceKey to the caller. Use
// HandleDeviceKeyStatus to learn whether a key exists.
func HandleGetDeviceKey(d Deps, req proto.GetDeviceKeyRequest) proto.BaseResponse {
	d.Logger.Println("key retrieval request processing...")
	key, err := keychain.GetDeviceKey(d.Store)
	if err != nil {
		d.Logger.Printf("key retrieval error: %v", err)
		// ErrSecretNotFound → not_found; other keychain errors → internal_error.
		// Uses CodeForError mapping.
		return errs.Response(err)
	}
	return proto.BaseResponse{Success: true, Data: proto.GetDeviceKeyResponseData{Key: key}}
}

// HandleSaveDeviceKey handles device key save requests.
//
// Deprecated: accepts a deviceKey the caller generated. Use
// HandleDeviceKeyEnsure, which generates it inside Keeper.
func HandleSaveDeviceKey(d Deps, req proto.SaveDeviceKeyRequest) proto.BaseResponse {
	d.Logger.Println("key save request processing...")
	if err := keychain.SaveDeviceKey(d.Store, req.Key); err != nil {
		d.Logger.Printf("key save error: %v", err)
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "key save failed: "+err.Error())
	}
	return proto.BaseResponse{Success: true}
}

// HandleDeleteDeviceKey handles device key deletion requests.
func HandleDeleteDeviceKey(d Deps, req proto.DeleteDeviceKeyRequest) proto.BaseResponse {
	d.Logger.Println("key delete request processing...")
	if err := keychain.DeleteDeviceKey(d.Store); err != nil {
		d.Logger.Printf("key delete error: %v", err)
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "key delete failed: "+err.Error())
	}
	return proto.BaseResponse{Success: true}
}

// HandleDeviceKeyStatus reports whether a device key is stored. The key is read
// only to check its shape and is never returned.
func HandleDeviceKeyStatus(d Deps, req proto.DeviceKeyStatusRequest) proto.BaseResponse {
	d.Logger.Println("device key status processing...")
	present, err := keychain.DeviceKeyPresent(d.Store)
	if err != nil {
		d.Logger.Printf("device key status error: %s", deviceKeyErrorClass(err))
		return deviceKeyErrorResponse(err, "failed to read device key")
	}
	return proto.BaseResponse{Success: true, Data: proto.DeviceKeyStatusResponseData{Present: present}}
}

// HandleDeviceKeyEnsure creates the device key inside Keeper when none is
// stored. Repeating it changes nothing and answers created=false.
func HandleDeviceKeyEnsure(d Deps, req proto.DeviceKeyEnsureRequest) proto.BaseResponse {
	d.Logger.Println("device key ensure processing...")
	created, response := ensureDeviceKey(d)
	if !response.Success {
		return response
	}
	return proto.BaseResponse{Success: true, Data: proto.DeviceKeyEnsureResponseData{Created: created}}
}

var errDeviceKeyGeneration = errors.New("device key generation failed")

// ensureDeviceKey is the one place a device key is minted, shared by
// device_key_ensure and auth_signup_prepare.
func ensureDeviceKey(d Deps) (bool, proto.BaseResponse) {
	created, err := keychain.EnsureDeviceKey(d.Store, func() (string, error) {
		raw := make([]byte, 32)
		defer secure.Zeroize(raw)
		if err := d.FillRandom(raw); err != nil {
			return "", errDeviceKeyGeneration
		}
		return base64.StdEncoding.EncodeToString(raw), nil
	})
	if err != nil {
		d.Logger.Printf("device key ensure error: %s", deviceKeyErrorClass(err))
		if errors.Is(err, errDeviceKeyGeneration) {
			return false, errs.CodeResponse(errs.ErrCodeInternal, "failed to generate device key")
		}
		return false, deviceKeyErrorResponse(err, "failed to store device key")
	}
	if created {
		d.Logger.Println("device key created")
	}
	return created, proto.BaseResponse{Success: true}
}

// deviceKeyErrorClass names the failure without the underlying error text, so
// no keychain backend message can carry stored bytes into the log.
func deviceKeyErrorClass(err error) string {
	switch {
	case errors.Is(err, keychain.ErrInvalidDeviceKey):
		return "invalid stored key"
	case errors.Is(err, errDeviceKeyGeneration):
		return "generation"
	default:
		return "keychain"
	}
}

func deviceKeyErrorResponse(err error, fallback string) proto.BaseResponse {
	if errors.Is(err, keychain.ErrInvalidDeviceKey) {
		return errs.CodeResponse(errs.ErrCodeStorageFailure, keychain.ErrInvalidDeviceKey.Error())
	}
	return errs.CodeResponse(errs.ErrCodeStorageFailure, fallback)
}
