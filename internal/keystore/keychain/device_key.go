package keychain

// device_key.go — Device key CRUD against a SecretStore.
//
// The device-key helper bodies from storage.go moved here as exported free
// functions; the keystore root's thin `*App` wrapper passes `a.Store` as the
// first argument to delegate — zero change to external signatures.
//
// The device key is a 32B AES-GCM key (stored Base64-encoded). It is used to
// wrap personal DEKs and never leaves the OS Keychain. The voluntary rotation
// flow (rotate_device_key composite action) also operates through this layer.

import "github.com/dragpass/keeper/config"

// SaveDeviceKey stores the device key (Base64-encoded 32B AES-GCM key).
func SaveDeviceKey(store SecretStore, key string) error {
	return store.Set(config.Service, config.DeviceKey, key)
}

// GetDeviceKey returns the device key (Base64-encoded 32B AES-GCM key).
func GetDeviceKey(store SecretStore) (string, error) {
	return store.Get(config.Service, config.DeviceKey)
}

// DeleteDeviceKey removes the device key.
func DeleteDeviceKey(store SecretStore) error {
	return store.Delete(config.Service, config.DeviceKey)
}
