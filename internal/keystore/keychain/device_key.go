package keychain

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
