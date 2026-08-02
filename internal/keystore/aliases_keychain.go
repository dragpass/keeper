// Keep the keychain aliases used by the root package and main.

package keystore

import "github.com/dragpass/keeper/internal/keystore/keychain"

type (
	SecretStore        = keychain.SecretStore
	KeyringSecretStore = keychain.KeyringSecretStore
)

var (
	ErrSecretNotFound           = keychain.ErrSecretNotFound
	ErrServerKeyVersionNotFound = keychain.ErrServerKeyVersionNotFound
	ErrNoActiveServerKey        = keychain.ErrNoActiveServerKey
	LoadE2EKeyringFile          = keychain.LoadE2EKeyringFile
	NewMemorySecretStore        = keychain.NewMemorySecretStore
)
