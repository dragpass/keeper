package keychain

// Server public key storage schema:
//
//   server_public_key_v{N}                 PEM (Nth production key)
//   server_public_key_active_version       "1" / "2" / ... string pointer
//   server_public_key_root_fingerprint     "sha256:..." TOFU pin (optional)

import (
	"errors"
	"fmt"
	"strconv"

	"github.com/dragpass/keeper/config"
)

// ErrServerKeyVersionNotFound is returned when the requested version slot is
// empty.
var ErrServerKeyVersionNotFound = errors.New("server public key version not found")

// ErrNoActiveServerKey is returned when the active version pointer is empty
// (pre-bootstrap).
var ErrNoActiveServerKey = errors.New("no active server public key")

func versionedServerKeyAccount(version uint) string {
	return fmt.Sprintf("%s%d", config.DragPassServerPublicKeyVersionedPrefix, version)
}

// SaveServerPublicKeyForVersion stores the PEM for the Nth version into the
// SecretStore.
func SaveServerPublicKeyForVersion(store SecretStore, version uint, pem string) error {
	if version == 0 {
		return errors.New("version must be >= 1")
	}
	if pem == "" {
		return errors.New("pem is empty")
	}
	return store.Set(config.Service, versionedServerKeyAccount(version), pem)
}

// GetServerPublicKeyByVersion reads the PEM for the Nth version from the
// SecretStore.
func GetServerPublicKeyByVersion(store SecretStore, version uint) (string, error) {
	if version == 0 {
		return "", errors.New("version must be >= 1")
	}
	pem, err := store.Get(config.Service, versionedServerKeyAccount(version))
	if err != nil || pem == "" {
		return "", ErrServerKeyVersionNotFound
	}
	return pem, nil
}

// DeleteServerPublicKeyForVersion removes the Nth version slot. (Used for
// revoked-key cleanup. Currently no callers — planned for future use.)
func DeleteServerPublicKeyForVersion(store SecretStore, version uint) error {
	if version == 0 {
		return errors.New("version must be >= 1")
	}
	return store.Delete(config.Service, versionedServerKeyAccount(version))
}

// SaveActiveServerKeyVersion updates the active version pointer.
func SaveActiveServerKeyVersion(store SecretStore, version uint) error {
	if version == 0 {
		return errors.New("version must be >= 1")
	}
	return store.Set(config.Service, config.DragPassServerPublicKeyActiveVersion, strconv.FormatUint(uint64(version), 10))
}

// GetActiveServerKeyVersion returns the current active version number.
// Returns ErrNoActiveServerKey if the pointer is empty.
func GetActiveServerKeyVersion(store SecretStore) (uint, error) {
	val, err := store.Get(config.Service, config.DragPassServerPublicKeyActiveVersion)
	if err != nil || val == "" {
		return 0, ErrNoActiveServerKey
	}
	n, err := strconv.ParseUint(val, 10, 32)
	if err != nil || n == 0 {
		return 0, fmt.Errorf("invalid active version pointer %q: %v", val, err)
	}
	return uint(n), nil
}

// GetActiveServerPublicKey returns the PEM for the active version.
func GetActiveServerPublicKey(store SecretStore) (string, error) {
	version, err := GetActiveServerKeyVersion(store)
	if err != nil {
		return "", err
	}
	pem, err := GetServerPublicKeyByVersion(store, version)
	if err != nil {
		return "", fmt.Errorf("active version v%d not stored: %w", version, err)
	}
	return pem, nil
}

// GetServerPublicKeyForVersion resolves zero to the active version.
func GetServerPublicKeyForVersion(store SecretStore, version uint) (string, error) {
	if version == 0 {
		return GetActiveServerPublicKey(store)
	}
	return GetServerPublicKeyByVersion(store, version)
}

// SaveRootPublicKeyFingerprint TOFU-pins the Root pubkey fingerprint.
// No-op on empty string (Root-not-configured environment).
func SaveRootPublicKeyFingerprint(store SecretStore, fp string) error {
	if fp == "" {
		return nil
	}
	return store.Set(config.Service, config.DragPassServerRootPublicKeyFingerprint, fp)
}

// GetRootPublicKeyFingerprint returns the fingerprint stored in the
// SecretStore, or "" if missing.
func GetRootPublicKeyFingerprint(store SecretStore) (string, error) {
	val, err := store.Get(config.Service, config.DragPassServerRootPublicKeyFingerprint)
	if err != nil {
		// keyring's not-found can surface as various error types, so
		// normalize to an empty value.
		return "", nil
	}
	return val, nil
}
