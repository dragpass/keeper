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

// DeleteArchivePrivateKey removes the archive private key PEM. Used by
// archive_key_split after the key has been Shamir-split into shares — at rest,
// the whole private key then exists nowhere. The public key slot is kept (the
// org still has an archive key; rotation keeps wrapping OLD DEKs to it).
func DeleteArchivePrivateKey(store SecretStore) error {
	return store.Delete(config.Service, config.OrgArchivePrivateKey)
}

// Per-account Archive / Recovery receiving keypair. Separate from the org
// archive keypair above: the account key receives handoff grants and quorum
// shares wrapped to the account directory public key, and must survive the
// org-slot wipe that archive_key_split performs.

// SaveAccountArchivePrivateKey stores the account archive private key PEM.
func SaveAccountArchivePrivateKey(store SecretStore, privatePEM string) error {
	return store.Set(config.Service, config.AccountArchivePrivateKey, privatePEM)
}

// GetAccountArchivePrivateKey returns the account archive private key PEM.
func GetAccountArchivePrivateKey(store SecretStore) (string, error) {
	return store.Get(config.Service, config.AccountArchivePrivateKey)
}

// SaveAccountArchivePublicKey stores the account archive public key PEM.
func SaveAccountArchivePublicKey(store SecretStore, publicPEM string) error {
	return store.Set(config.Service, config.AccountArchivePublicKey, publicPEM)
}

// GetAccountArchivePublicKey returns the account archive public key PEM.
func GetAccountArchivePublicKey(store SecretStore) (string, error) {
	return store.Get(config.Service, config.AccountArchivePublicKey)
}

// Archive quorum recovery-session ephemeral keypair.

// SaveArchiveSessionPrivateKey stores the recovery-session private key PEM.
func SaveArchiveSessionPrivateKey(store SecretStore, privatePEM string) error {
	return store.Set(config.Service, config.OrgArchiveSessionPrivateKey, privatePEM)
}

// GetArchiveSessionPrivateKey returns the recovery-session private key PEM.
func GetArchiveSessionPrivateKey(store SecretStore) (string, error) {
	return store.Get(config.Service, config.OrgArchiveSessionPrivateKey)
}

// DeleteArchiveSessionPrivateKey removes the recovery-session private key PEM.
func DeleteArchiveSessionPrivateKey(store SecretStore) error {
	return store.Delete(config.Service, config.OrgArchiveSessionPrivateKey)
}

// SaveArchiveSessionPublicKey stores the recovery-session public key PEM.
func SaveArchiveSessionPublicKey(store SecretStore, publicPEM string) error {
	return store.Set(config.Service, config.OrgArchiveSessionPublicKey, publicPEM)
}

// DeleteArchiveSessionPublicKey removes the recovery-session public key PEM.
func DeleteArchiveSessionPublicKey(store SecretStore) error {
	return store.Delete(config.Service, config.OrgArchiveSessionPublicKey)
}
