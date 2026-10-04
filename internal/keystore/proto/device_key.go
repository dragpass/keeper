// device_key_models.go — DeviceKey CRUD request/response payloads.

package proto

// DeviceKeyStatusRequest takes no input.
type DeviceKeyStatusRequest struct{}

// DeviceKeyStatusResponseData says whether a device key is stored. It carries
// no key material by construction: the key never leaves the Keeper.
type DeviceKeyStatusResponseData struct {
	Present bool `json:"present"`
}

// DeviceKeyEnsureRequest takes no input; the key is generated inside Keeper.
type DeviceKeyEnsureRequest struct{}

// DeviceKeyEnsureResponseData says whether this call created the device key
// (false when one was already stored). It carries no key material.
type DeviceKeyEnsureResponseData struct {
	Created bool `json:"created"`
}
