package keychain

// server_keys.go — Multi-version server public key + Root fingerprint CRUD
// against a SecretStore.
//
// The `*App` method bodies from keystore root server_keys.go moved here as
// exported free functions; the keystore root's thin `*App` wrapper passes
// `a.Store` as the first argument to delegate — zero change to external
// signatures.
//
// Storage schema (see config/config.go constants):
//
//   server_public_key_v{N}                 PEM (Nth production key)
//   server_public_key_active_version       "1" / "2" / ... string pointer
//   server_public_key_root_fingerprint     "sha256:..." TOFU pin (optional)
//   server_public_key                      active key PEM mirror (legacy
//                                          compatibility)

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

// versionedServerKeyAccount returns the SecretStore account for a given
// versioned server public key slot. Unexported — only used by other functions
// in this file.
func versionedServerKeyAccount(version uint) string {
	return fmt.Sprintf("%s%d", config.DragPassServerPublicKeyVersionedPrefix, version)
}

// SaveServerPublicKey stores the legacy single-slot active server public key
// PEM mirror (for pre-13b Extension compatibility).
func SaveServerPublicKey(store SecretStore, serverPublicKey string) error {
	return store.Set(config.Service, config.DragPassServerPublicKey, serverPublicKey)
}

// GetServerPublicKey returns the legacy single-slot server public key PEM
// mirror (active key mirror for pre-13b Extension compatibility).
func GetServerPublicKey(store SecretStore) (string, error) {
	return store.Get(config.Service, config.DragPassServerPublicKey)
}

// DeleteServerPublicKey removes the legacy single-slot server public key PEM.
func DeleteServerPublicKey(store SecretStore) error {
	return store.Delete(config.Service, config.DragPassServerPublicKey)
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
// A fallback entry point for older Extensions that do not pass
// server_key_version.
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

// GetServerPublicKeyForVersion is the unified entry point used by challenge
// verification. version == 0 means active fallback; otherwise the exact
// version.
func GetServerPublicKeyForVersion(store SecretStore, version uint) (string, error) {
	if version == 0 {
		// Older Extensions (no field sent) fall back to active. If bootstrap
		// has completed, active = v1 is filled.
		if pem, err := GetActiveServerPublicKey(store); err == nil {
			return pem, nil
		}
		// Abnormal / pre-boot case where the active pointer is empty: fall
		// back to the legacy single slot.
		return GetServerPublicKey(store)
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
