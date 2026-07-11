package keychain

// archive_key.go — per-org Archive / Recovery keypair CRUD.
//
// A slot completely separate from the account identity keypair (RSA,
// keypair.go) and the request-signing key (request_key.go). Stores the org
// break-glass recovery keypair as PEM strings. The private key never leaves
// this slot — only public-key material and fingerprints cross into the
// Extension.

import "github.com/dragpass/keeper/config"

// SaveArchivePrivateKey stores the RSA archive private key PEM.
func SaveArchivePrivateKey(store SecretStore, privatePEM string) error {
	return store.Set(config.Service, config.OrgArchivePrivateKey, privatePEM)
}

// GetArchivePrivateKey returns the stored archive private key PEM.
func GetArchivePrivateKey(store SecretStore) (string, error) {
	return store.Get(config.Service, config.OrgArchivePrivateKey)
}

// SaveArchivePublicKey stores the RSA archive public key PEM.
func SaveArchivePublicKey(store SecretStore, publicPEM string) error {
	return store.Set(config.Service, config.OrgArchivePublicKey, publicPEM)
}

// GetArchivePublicKey returns the stored archive public key PEM.
func GetArchivePublicKey(store SecretStore) (string, error) {
	return store.Get(config.Service, config.OrgArchivePublicKey)
}
