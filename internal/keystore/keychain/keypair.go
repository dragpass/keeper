package keychain

import "github.com/dragpass/keeper/config"

// SavePrivateKey stores the active Keeper RSA private key PEM.
func SavePrivateKey(store SecretStore, privateKey string) error {
	return store.Set(config.Service, config.DragPassKeeperPrivateKey, privateKey)
}

// GetPrivateKey returns the active Keeper RSA private key PEM.
func GetPrivateKey(store SecretStore) (string, error) {
	return store.Get(config.Service, config.DragPassKeeperPrivateKey)
}

// DeletePrivateKey removes the active Keeper RSA private key PEM.
func DeletePrivateKey(store SecretStore) error {
	return store.Delete(config.Service, config.DragPassKeeperPrivateKey)
}

// SavePublicKey stores the active Keeper RSA public key PEM.
func SavePublicKey(store SecretStore, publicKey string) error {
	return store.Set(config.Service, config.DragPassKeeperPublicKey, publicKey)
}

// GetPublicKey returns the active Keeper RSA public key PEM.
func GetPublicKey(store SecretStore) (string, error) {
	return store.Get(config.Service, config.DragPassKeeperPublicKey)
}

// DeletePublicKey removes the active Keeper RSA public key PEM.
func DeletePublicKey(store SecretStore) error {
	return store.Delete(config.Service, config.DragPassKeeperPublicKey)
}
