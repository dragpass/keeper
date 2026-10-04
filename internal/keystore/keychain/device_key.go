package keychain

import (
	"encoding/base64"
	"errors"

	"github.com/dragpass/keeper/config"
	"github.com/dragpass/keeper/internal/keystore/secure"
)

// SaveDeviceKey stores the device key (Base64-encoded 32B AES-GCM key).
func SaveDeviceKey(store SecretStore, key string) error {
	return withPersonalKeyBundleLock(store, func() error {
		if err := recoverPersonalKeyBundleLocked(store); err != nil {
			return err
		}
		return saveDeviceKeyLocked(store, key)
	})
}

// GetDeviceKey returns the device key (Base64-encoded 32B AES-GCM key).
func GetDeviceKey(store SecretStore) (string, error) {
	var key string
	err := withPersonalKeyBundleLock(store, func() error {
		if err := recoverPersonalKeyBundleLocked(store); err != nil {
			return err
		}
		var err error
		key, err = getDeviceKeyLocked(store)
		return err
	})
	return key, err
}

// DeleteDeviceKey removes the device key.
func DeleteDeviceKey(store SecretStore) error {
	return withPersonalKeyBundleLock(store, func() error {
		if err := recoverPersonalKeyBundleLocked(store); err != nil {
			return err
		}
		return store.Delete(config.Service, config.DeviceKey)
	})
}

func saveDeviceKeyLocked(store SecretStore, key string) error {
	return store.Set(config.Service, config.DeviceKey, key)
}

func getDeviceKeyLocked(store SecretStore) (string, error) {
	return store.Get(config.Service, config.DeviceKey)
}

// ErrInvalidDeviceKey reports a stored device key that is not Base64 of 32
// bytes. It is never repaired: replacing it would orphan the device-wrapped
// DEK the old value sealed, so the caller surfaces it instead.
var ErrInvalidDeviceKey = errors.New("stored device key is invalid")

// DeviceKeyPresent reports whether a valid device key is stored, without
// returning it.
func DeviceKeyPresent(store SecretStore) (bool, error) {
	var present bool
	err := withPersonalKeyBundleLock(store, func() error {
		if err := recoverPersonalKeyBundleLocked(store); err != nil {
			return err
		}
		var err error
		present, err = deviceKeyPresentLocked(store)
		return err
	})
	return present, err
}

// EnsureDeviceKey stores the key newKey returns when no device key exists and
// reports whether it wrote one. The check and the write share the keychain
// process lock, so two Keeper processes racing on a fresh device store one
// key, not two that each believe theirs is current.
func EnsureDeviceKey(store SecretStore, newKey func() (string, error)) (bool, error) {
	var created bool
	err := withPersonalKeyBundleLock(store, func() error {
		if err := recoverPersonalKeyBundleLocked(store); err != nil {
			return err
		}
		present, err := deviceKeyPresentLocked(store)
		if err != nil || present {
			return err
		}
		key, err := newKey()
		if err != nil {
			return err
		}
		if err := saveDeviceKeyLocked(store, key); err != nil {
			return err
		}
		created = true
		return nil
	})
	return created, err
}

func deviceKeyPresentLocked(store SecretStore) (bool, error) {
	stored, err := getDeviceKeyLocked(store)
	if errors.Is(err, ErrSecretNotFound) || (err == nil && stored == "") {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	raw, err := base64.StdEncoding.DecodeString(stored)
	valid := err == nil && len(raw) == 32
	secure.Zeroize(raw)
	if !valid {
		return false, ErrInvalidDeviceKey
	}
	return true, nil
}
