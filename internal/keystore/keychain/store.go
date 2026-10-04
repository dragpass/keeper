// Package keychain abstracts platform secret storage.
package keychain

import (
	"errors"

	"github.com/zalando/go-keyring"
)

// ErrSecretNotFound lets SecretStore implementations return a consistent
// sentinel. The keyring package exposes `keyring.ErrNotFound`, but importing
// that directly from external code increases coupling, so this alias lives
// inside the keystore package.
var ErrSecretNotFound = errors.New("secret not found")

// SecretStore is the minimum contract for an OS Keychain-style secret store.
// Get / Set / Delete cover every storage flow in the keystore package.
//
//   - Get: returns ErrSecretNotFound (or a wrapping error) when missing.
//   - Set: calling twice on the same (service, account) overwrites.
//   - Delete: deleting a missing entry may return an error (same as keyring).
type SecretStore interface {
	Get(service, account string) (string, error)
	Set(service, account, value string) error
	Delete(service, account string) error
}

// KeyringSecretStore uses the platform keyring and the configured e2e mirror.
type KeyringSecretStore struct{}

func (KeyringSecretStore) usesPlatformKeyring() {}

func (KeyringSecretStore) Get(service, account string) (string, error) {
	v, err := krGet(service, account)
	if err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			return "", ErrSecretNotFound
		}
		return "", err
	}
	return v, nil
}

func (KeyringSecretStore) Set(service, account, value string) error {
	return krSet(service, account, value)
}

func (KeyringSecretStore) Delete(service, account string) error {
	return krDelete(service, account)
}
