// device_key.go — DeviceKey CRUD handlers.
// HandleGetDeviceKey / HandleSaveDeviceKey / HandleDeleteDeviceKey —
// three actions routed by the dispatcher. Manages the 32B AES-GCM deviceKey
// in the OS Keychain.

package handlers

import (
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// HandleGetDeviceKey handles device key retrieval requests.
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
