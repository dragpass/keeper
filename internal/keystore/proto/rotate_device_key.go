// rotate_device_key_models.go — DeviceKey voluntary rotation payload.

package proto

// ────────────────────────────────────────────────────────────────────────
// DeviceKey voluntary rotation (single composite action).
//
// Takes the current device-wrapped personal DEK (Base64 iv||ct) as input
// and handles unwrap → generate a new deviceKey → wrap with the new
// deviceKey → save to Keychain inside the Keeper in one shot. The raw
// 32B personal DEK does not live in the Extension JS heap.
// ────────────────────────────────────────────────────────────────────────

// RotateDeviceKeyRequest — Base64 of the raw bytes the Extension decoded
// from the current device-wrapped DEK in deviceMasterStorage Braille.
type RotateDeviceKeyRequest struct {
	DeviceWrappedDEKB64 string `json:"device_wrapped_dek_b64"`
}

func (r RotateDeviceKeyRequest) Validate() error {
	_, err := requireBase64(r.DeviceWrappedDEKB64, "device_wrapped_dek_b64")
	return err
}

// RotateDeviceKeyResponseData — result wrapped with the new deviceKey.
// The Extension Braille-encodes it and overwrites deviceMasterStorage.
type RotateDeviceKeyResponseData struct {
	DeviceWrappedDEKB64 string `json:"device_wrapped_dek_b64"`
}
