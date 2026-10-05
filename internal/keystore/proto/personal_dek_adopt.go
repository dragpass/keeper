// personal_dek_adopt.go — adopting a device-wrapped personal DEK the
// Extension still holds into the Keeper slot (0.0.58).

package proto

import "encoding/base64"

// DeviceWrappedDEKLen is iv(12) || AES-GCM(32B DEK) || tag(16): the only
// shape a device wrap of the personal DEK takes.
const DeviceWrappedDEKLen = 12 + 32 + 16

// Reasons PersonalDEKAdoptResponseData gives when it did not adopt.
const (
	PersonalDEKAdoptReasonSignedOut    = "signed_out"
	PersonalDEKAdoptReasonSlotOccupied = "slot_occupied"
)

// PersonalDEKAdoptRequest carries the Extension's old copy of the device
// master, Base64(iv(12) || ciphertext_with_tag). Ciphertext, not key
// material: it opens only with the device key, which never crosses IPC.
type PersonalDEKAdoptRequest struct {
	DeviceWrappedDEKB64 string `json:"device_wrapped_dek_b64"`
}

// Validate requires standard Base64, the encoding every slot reader
// decodes, of exactly one device wrap.
func (r PersonalDEKAdoptRequest) Validate() error {
	if r.DeviceWrappedDEKB64 == "" {
		return newValidationError("device_wrapped_dek_b64", "must not be empty")
	}
	raw, err := base64.StdEncoding.DecodeString(r.DeviceWrappedDEKB64)
	if err != nil {
		return newValidationError("device_wrapped_dek_b64", "must be valid standard Base64")
	}
	if len(raw) != DeviceWrappedDEKLen {
		return newValidationError("device_wrapped_dek_b64", "must decode to 60 bytes (iv || ciphertext || tag)")
	}
	return nil
}

// PersonalDEKAdoptResponseData says whether the slot now holds the copy.
// Reason is set only when it does not: signed_out or slot_occupied.
type PersonalDEKAdoptResponseData struct {
	Adopted bool   `json:"adopted"`
	Reason  string `json:"reason,omitempty"`
}
