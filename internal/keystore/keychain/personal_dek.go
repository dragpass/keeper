package keychain

import (
	"errors"

	"github.com/dragpass/keeper/config"
)

func SavePersonalDeviceWrappedDEK(store SecretStore, wrapped string) error {
	return withPersonalKeyBundleLock(store, func() error {
		if err := recoverPersonalKeyBundleLocked(store); err != nil {
			return err
		}
		return savePersonalDeviceWrappedDEKLocked(store, wrapped)
	})
}

func GetPersonalDeviceWrappedDEK(store SecretStore) (string, error) {
	var wrapped string
	err := withPersonalKeyBundleLock(store, func() error {
		if err := recoverPersonalKeyBundleLocked(store); err != nil {
			return err
		}
		var err error
		wrapped, err = getPersonalDeviceWrappedDEKLocked(store)
		return err
	})
	return wrapped, err
}

func DeletePersonalDeviceWrappedDEK(store SecretStore) error {
	return withPersonalKeyBundleLock(store, func() error {
		if err := recoverPersonalKeyBundleLocked(store); err != nil {
			return err
		}
		return store.Delete(config.Service, config.PersonalDeviceWrappedDEK)
	})
}

func savePersonalDeviceWrappedDEKLocked(store SecretStore, wrapped string) error {
	return store.Set(config.Service, config.PersonalDeviceWrappedDEK, wrapped)
}

func getPersonalDeviceWrappedDEKLocked(store SecretStore) (string, error) {
	return store.Get(config.Service, config.PersonalDeviceWrappedDEK)
}

func SavePendingSignupDeviceWrappedDEK(store SecretStore, wrapped string) error {
	return withPersonalKeyBundleLock(store, func() error {
		return store.Set(config.Service, config.PendingSignupPersonalDEK, wrapped)
	})
}

func GetPendingSignupDeviceWrappedDEK(store SecretStore) (string, error) {
	return store.Get(config.Service, config.PendingSignupPersonalDEK)
}

// PromotePendingSignupDEK finishes a signup's key state. keypairPromoted says
// whether this save_session_code just promoted the signup's pending keypair:
// only then does the pending DEK become the personal DEK. Otherwise a pending
// DEK is left over from an abandoned signup and is dropped, so an unrelated
// login can never swap the personal DEK. A second call finds nothing pending
// and changes nothing.
func PromotePendingSignupDEK(store SecretStore, keypairPromoted bool) error {
	return withPersonalKeyBundleLock(store, func() error {
		return promotePendingSignupDEKLocked(store, keypairPromoted)
	})
}

func promotePendingSignupDEKLocked(store SecretStore, keypairPromoted bool) error {
	pending, err := store.Get(config.Service, config.PendingSignupPersonalDEK)
	if errors.Is(err, ErrSecretNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if keypairPromoted {
		if err := recoverPersonalKeyBundleLocked(store); err != nil {
			return err
		}
		if err := savePersonalDeviceWrappedDEKLocked(store, pending); err != nil {
			return err
		}
	}
	if err := store.Delete(config.Service, config.PendingSignupPersonalDEK); err != nil && !errors.Is(err, ErrSecretNotFound) {
		return err
	}
	return nil
}

func DeletePendingSignupDeviceWrappedDEK(store SecretStore) error {
	return withPersonalKeyBundleLock(store, func() error {
		return store.Delete(config.Service, config.PendingSignupPersonalDEK)
	})
}
