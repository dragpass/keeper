package keychain

import "github.com/dragpass/keeper/config"

func SavePersonalDeviceWrappedDEK(store SecretStore, wrapped string) error {
	return withPersonalKeyBundleLock(store, func() error {
		if err := recoverPersonalKeyBundleLocked(store); err != nil {
			return err
		}
		return savePersonalDeviceWrappedDEKLocked(store, wrapped)
	})
}

func GetPersonalDeviceWrappedDEK(store SecretStore) (string, error) {
	var wrapped string
	err := withPersonalKeyBundleLock(store, func() error {
		if err := recoverPersonalKeyBundleLocked(store); err != nil {
			return err
		}
		var err error
		wrapped, err = getPersonalDeviceWrappedDEKLocked(store)
		return err
	})
	return wrapped, err
}

func DeletePersonalDeviceWrappedDEK(store SecretStore) error {
	return withPersonalKeyBundleLock(store, func() error {
		if err := recoverPersonalKeyBundleLocked(store); err != nil {
			return err
		}
		return store.Delete(config.Service, config.PersonalDeviceWrappedDEK)
	})
}

func savePersonalDeviceWrappedDEKLocked(store SecretStore, wrapped string) error {
	return store.Set(config.Service, config.PersonalDeviceWrappedDEK, wrapped)
}

func getPersonalDeviceWrappedDEKLocked(store SecretStore) (string, error) {
	return store.Get(config.Service, config.PersonalDeviceWrappedDEK)
}
