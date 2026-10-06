// device_identity.go — device id, account binding and device sign-out
// (0.0.58, App and Extension independence design §2.1, §2.2, §4.3).
//
// The Keeper owns one device id per machine, so the App and the Extension
// stop showing up as two server devices and the MLS leaf stays on the id it
// was declared for. The account binding tells the Extension which account
// the App signed in to here; it is a hint, and the sign-in is judged by the
// server's answer and the active account key, never by this record.
//
// Logs name the failure class only: a keychain backend message is not
// trusted to be free of stored bytes.

package handlers

import (
	"errors"

	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

var errDeviceIDGeneration = errors.New("device id generation failed")

// HandleDeviceIDEnsure returns this machine's device id, choosing and
// storing it on the first call.
func HandleDeviceIDEnsure(d Deps, req proto.DeviceIDEnsureRequest) proto.BaseResponse {
	id, source, err := keychain.EnsureDeviceID(d.Store, func() (string, keychain.DeviceIDSource, error) {
		if req.CandidateDeviceID != "" {
			return req.CandidateDeviceID, keychain.DeviceIDCandidate, nil
		}
		generated, err := d.newUUID()
		if err != nil {
			return "", "", errDeviceIDGeneration
		}
		return generated, keychain.DeviceIDGenerated, nil
	})
	if err != nil {
		d.Logger.Printf("device id ensure error: %s", deviceIdentityErrorClass(err))
		return deviceIdentityErrorResponse(err)
	}
	d.Logger.Printf("device id ensure: %s", source)
	return proto.BaseResponse{Success: true, Data: proto.DeviceIDEnsureResponseData{DeviceID: id, Source: string(source)}}
}

// HandleAccountBindingSet records the account the App signed in to. It
// requires an active account key: a binding on a device with no account key
// would invite a sign-in that cannot succeed.
func HandleAccountBindingSet(d Deps, req proto.AccountBindingSetRequest) proto.BaseResponse {
	if publicKey, err := keychain.GetPublicKey(d.Store); err != nil || publicKey == "" {
		return errs.CodeResponse(errs.ErrCodeNotFound, "no active account key")
	}
	binding, changed, err := keychain.SetAccountBinding(d.Store, req.AccountID, req.Alias, req.Renew)
	if err != nil {
		d.Logger.Printf("account binding set error: %s", deviceIdentityErrorClass(err))
		return deviceIdentityErrorResponse(err)
	}
	d.Logger.Printf("account binding set: changed=%t", changed)
	return proto.BaseResponse{Success: true, Data: proto.AccountBindingSetResponseData{
		Changed: changed, Generation: binding.Generation,
	}}
}

// HandleDeviceAccountStatus reports the device id, the binding, the active
// account key's fingerprint and whether a device master is stored. It writes
// nothing: an absent device id stays absent until device_id_ensure.
//
// device_master_present needs both the device-wrapped personal DEK and the
// device key that opens it; one without the other cannot open a personal
// token, and the Extension must not sign itself in on it.
func HandleDeviceAccountStatus(d Deps, _ proto.DeviceAccountStatusRequest) proto.BaseResponse {
	deviceID, _, err := keychain.GetDeviceID(d.Store)
	if err != nil {
		d.Logger.Printf("device account status error: %s", deviceIdentityErrorClass(err))
		return deviceIdentityErrorResponse(err)
	}
	binding, _, err := keychain.GetAccountBinding(d.Store)
	if err != nil {
		d.Logger.Printf("device account status error: %s", deviceIdentityErrorClass(err))
		return deviceIdentityErrorResponse(err)
	}
	data := proto.DeviceAccountStatusResponseData{
		DeviceID:   deviceID,
		AccountID:  binding.AccountID,
		Alias:      binding.Alias,
		Generation: binding.Generation,
		SignedOut:  binding.SignedOut,
	}
	if publicKey, err := keychain.GetPublicKey(d.Store); err == nil && publicKey != "" {
		data.AccountKeyFingerprint = crypto.AccountKeyFingerprint([]byte(publicKey))
	}
	present, err := deviceMasterPresent(d)
	if err != nil {
		d.Logger.Printf("device account status error: %s", deviceIdentityErrorClass(err))
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "failed to read the device master")
	}
	data.DeviceMasterPresent = present
	return proto.BaseResponse{Success: true, Data: data}
}

// HandleDeviceSignout is "sign out on this device" on the Keeper's side: the
// device master goes, the binding is marked signed out, and this process's
// group session handles close. The account key, device key, request key, MLS
// leaf and pins stay, so the next password sign-in on the App restores the
// device without a recovery key (design Q3).
func HandleDeviceSignout(d Deps, _ proto.DeviceSignoutRequest) proto.BaseResponse {
	removed, binding, err := keychain.SignOutDevice(d.Store)
	if err != nil {
		d.Logger.Printf("device signout error: %s", deviceIdentityErrorClass(err))
		return deviceIdentityErrorResponse(err)
	}
	closed := 0
	if d.GroupSessions != nil {
		closed = d.GroupSessions.CloseAll()
	}
	d.Logger.Printf("device signout: device master removed=%t, closed %d group session(s)", removed, closed)
	return proto.BaseResponse{Success: true, Data: proto.DeviceSignoutResponseData{
		DeviceMasterRemoved: removed, ClosedGroupSessions: closed, Generation: binding.Generation,
	}}
}

func deviceMasterPresent(d Deps) (bool, error) {
	wrapped, err := keychain.GetPersonalDeviceWrappedDEK(d.Store)
	if errors.Is(err, keychain.ErrSecretNotFound) || (err == nil && wrapped == "") {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return keychain.DeviceKeyPresent(d.Store)
}

// newUUID is a random version 4 UUID in the lowercase form device ids take.
func (d Deps) newUUID() (string, error) {
	var b [16]byte
	if err := d.FillRandom(b[:]); err != nil {
		return "", err
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	const hex = "0123456789abcdef"
	out := make([]byte, 0, 36)
	for i, c := range b {
		if i == 4 || i == 6 || i == 8 || i == 10 {
			out = append(out, '-')
		}
		out = append(out, hex[c>>4], hex[c&0x0f])
	}
	return string(out), nil
}

func deviceIdentityErrorClass(err error) string {
	switch {
	case errors.Is(err, keychain.ErrInvalidDeviceID):
		return "invalid device id"
	case errors.Is(err, keychain.ErrInvalidAccountBinding):
		return "invalid account binding"
	case errors.Is(err, keychain.ErrUnreadableLeaf):
		return "unreadable mls leaf record"
	case errors.Is(err, keychain.ErrInvalidDeviceKey):
		return "invalid stored device key"
	case errors.Is(err, errDeviceIDGeneration):
		return "generation"
	default:
		return "keychain"
	}
}

func deviceIdentityErrorResponse(err error) proto.BaseResponse {
	switch {
	case errors.Is(err, errDeviceIDGeneration):
		return errs.CodeResponse(errs.ErrCodeInternal, "failed to generate a device id")
	case errors.Is(err, keychain.ErrInvalidDeviceID):
		return errs.CodeResponse(errs.ErrCodeStorageFailure, keychain.ErrInvalidDeviceID.Error())
	case errors.Is(err, keychain.ErrInvalidAccountBinding):
		return errs.CodeResponse(errs.ErrCodeStorageFailure, keychain.ErrInvalidAccountBinding.Error())
	case errors.Is(err, keychain.ErrUnreadableLeaf):
		return errs.CodeResponse(errs.ErrCodeStorageFailure, keychain.ErrUnreadableLeaf.Error())
	default:
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "device identity storage failed")
	}
}
