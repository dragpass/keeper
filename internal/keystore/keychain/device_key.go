package keychain

import "github.com/dragpass/keeper/config"

// SaveDeviceKey stores the device key (Base64-encoded 32B AES-GCM key).
func SaveDeviceKey(store SecretStore, key string) error {
	return withPersonalKeyBundleLock(store, func() error {
		if err := recoverPersonalKeyBundleLocked(store); err != nil {
			return err
		}
		return saveDeviceKeyLocked(store, key)
	})
}

// GetDeviceKey returns the device key (Base64-encoded 32B AES-GCM key).
func GetDeviceKey(store SecretStore) (string, error) {
	var key string
	err := withPersonalKeyBundleLock(store, func() error {
		if err := recoverPersonalKeyBundleLocked(store); err != nil {
			return err
		}
		var err error
		key, err = getDeviceKeyLocked(store)
		return err
	})
	return key, err
}

// DeleteDeviceKey removes the device key.
func DeleteDeviceKey(store SecretStore) error {
	return withPersonalKeyBundleLock(store, func() error {
		if err := recoverPersonalKeyBundleLocked(store); err != nil {
			return err
		}
		return store.Delete(config.Service, config.DeviceKey)
	})
}

func saveDeviceKeyLocked(store SecretStore, key string) error {
	return store.Set(config.Service, config.DeviceKey, key)
}

func getDeviceKeyLocked(store SecretStore) (string, error) {
	return store.Get(config.Service, config.DeviceKey)
}
