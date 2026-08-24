package keychain

import "github.com/dragpass/keeper/config"

func SavePersonalDeviceWrappedDEK(store SecretStore, wrapped string) error {
	return store.Set(config.Service, config.PersonalDeviceWrappedDEK, wrapped)
}

func GetPersonalDeviceWrappedDEK(store SecretStore) (string, error) {
	return store.Get(config.Service, config.PersonalDeviceWrappedDEK)
}

func DeletePersonalDeviceWrappedDEK(store SecretStore) error {
	return store.Delete(config.Service, config.PersonalDeviceWrappedDEK)
}
