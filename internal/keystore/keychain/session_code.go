package keychain

import "github.com/dragpass/keeper/config"

// SaveSessionCode stores the user's SessionCode.
func SaveSessionCode(store SecretStore, sessionCode string) error {
	return store.Set(config.Service, config.SessionCode, sessionCode)
}

// GetSessionCode returns the user's SessionCode.
func GetSessionCode(store SecretStore) (string, error) {
	return store.Get(config.Service, config.SessionCode)
}

// DeleteSessionCode removes the user's SessionCode.
func DeleteSessionCode(store SecretStore) error {
	return store.Delete(config.Service, config.SessionCode)
}
