package keychain

// keypair.go — Keypair (active) CRUD against a SecretStore.
//
// The `*App` method bodies from storage.go moved here as exported free
// functions; the keystore root's thin `*App` wrapper passes `a.Store` as the
// first argument to delegate — zero change to external signatures.
//
// This layer is a logic-free CRUD pass-through. SecretStore abstracts over
// the OS Keychain (production) / in-memory map (unit tests) / file mirror
// (e2e).

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
