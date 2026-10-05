// personal_dek_adopt.go — moves the Extension's old copy of the device
// master into the Keeper slot (0.0.58).
//
// Before 0.0.58 the Extension kept the device-wrapped personal DEK in its own
// storage. Its migration used to send that copy through
// dek_unwrap_and_encrypt_with_aad, which stored any supplied wrap in the
// slot. The Extension checked "slot empty, not signed out" first, but a
// device_signout or an App login could land between that check and the
// write, undoing the sign-out or replacing a fresh slot with the stale copy.
// This action does the check and the write in one hold of the keychain
// process lock, and is the only action that stores a caller-supplied wrap.
//
// Logs name the outcome or the failure class, never the wrap or a backend
// message.

package handlers

import (
	"encoding/base64"
	"errors"

	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/secure"
)

var errAdoptWrapDoesNotOpen = errors.New("device wrap does not open with the stored device key")

// HandlePersonalDEKAdopt stores the supplied device wrap in the slot when the
// slot is empty, the device is not signed out and the wrap opens with the
// stored device key. A refusal for either of the first two is a success with
// adopted false and a reason; a wrap that does not open is crypto_failure,
// no device key is not_found, and an unreadable keychain value is
// storage_failure. Nothing is written in any of those cases.
func HandlePersonalDEKAdopt(d Deps, req proto.PersonalDEKAdoptRequest) proto.BaseResponse {
	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}
	outcome, err := keychain.AdoptPersonalDeviceWrappedDEK(d.Store, req.DeviceWrappedDEKB64, func(deviceKeyB64 string) error {
		return deviceWrapOpens(deviceKeyB64, req.DeviceWrappedDEKB64)
	})
	switch {
	case errors.Is(err, errAdoptWrapDoesNotOpen):
		d.Logger.Println("personal dek adopt: wrap does not open")
		return errs.CodeResponse(errs.ErrCodeCryptoFailure, errAdoptWrapDoesNotOpen.Error())
	case errors.Is(err, keychain.ErrNoDeviceKey):
		d.Logger.Println("personal dek adopt: no device key")
		return errs.CodeResponse(errs.ErrCodeNotFound, "no device key on this device")
	case errors.Is(err, keychain.ErrInvalidDeviceKey):
		d.Logger.Println("personal dek adopt error: invalid stored device key")
		return errs.CodeResponse(errs.ErrCodeStorageFailure, keychain.ErrInvalidDeviceKey.Error())
	case errors.Is(err, keychain.ErrInvalidAccountBinding):
		d.Logger.Println("personal dek adopt error: invalid account binding")
		return errs.CodeResponse(errs.ErrCodeStorageFailure, keychain.ErrInvalidAccountBinding.Error())
	case err != nil:
		d.Logger.Println("personal dek adopt error: keychain")
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "failed to adopt the personal DEK")
	}

	data := proto.PersonalDEKAdoptResponseData{Adopted: outcome == keychain.AdoptStored}
	switch outcome {
	case keychain.AdoptSkippedSignedOut:
		data.Reason = proto.PersonalDEKAdoptReasonSignedOut
	case keychain.AdoptSkippedSlotOccupied:
		data.Reason = proto.PersonalDEKAdoptReasonSlotOccupied
	}
	d.Logger.Printf("personal dek adopt: adopted=%t reason=%s", data.Adopted, data.Reason)
	return proto.BaseResponse{Success: true, Data: data}
}

// deviceWrapOpens reports whether the wrap opens to a 32B DEK under the
// device key. The DEK and the decoded key are zeroized before it returns.
func deviceWrapOpens(deviceKeyB64, wrappedB64 string) error {
	deviceKey, err := base64.StdEncoding.DecodeString(deviceKeyB64)
	if err != nil || len(deviceKey) != 32 {
		secure.Zeroize(deviceKey)
		return keychain.ErrInvalidDeviceKey
	}
	defer secure.Zeroize(deviceKey)
	dek, err := unwrapDeviceWrappedDEK(deviceKey, wrappedB64)
	if err != nil {
		return errAdoptWrapDoesNotOpen
	}
	secure.Zeroize(dek)
	return nil
}
