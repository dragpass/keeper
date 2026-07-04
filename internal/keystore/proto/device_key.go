// device_key_models.go — DeviceKey CRUD request/response payloads.

package proto

type SaveDeviceKeyRequest struct {
	Key string `json:"key"`
}

func (r SaveDeviceKeyRequest) Validate() error {
	// device key is the Base64 of a 32B AES-GCM raw key.
	_, err := requireBase64Len(r.Key, "key", 32)
	return err
}

type GetDeviceKeyResponseData struct {
	Key string `json:"key"`
}
