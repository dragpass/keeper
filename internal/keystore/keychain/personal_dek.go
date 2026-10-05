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

// promotePendingSignupDEKLocked finishes a signup's key state under the
// personal key bundle lock AcceptSessionCode holds. keypairPromoted says
// whether this save_session_code just promoted the signup's pending keypair:
// only then does the pending DEK become the personal DEK. Otherwise a pending
// DEK is left over from an abandoned signup and is dropped, so an unrelated
// login can never swap the personal DEK. A second call finds nothing pending
// and changes nothing.
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

// AdoptOutcome is what AdoptPersonalDeviceWrappedDEK did.
type AdoptOutcome int

const (
	AdoptStored AdoptOutcome = iota
	AdoptSkippedSignedOut
	AdoptSkippedSlotOccupied
)

// ErrNoDeviceKey reports that no device key is stored, so no device wrap
// can be checked against it.
var ErrNoDeviceKey = errors.New("device key not found")

// AdoptPersonalDeviceWrappedDEK stores wrapped as the device master only
// when the binding is not signed out, the slot is empty and opens accepts
// wrapped under the stored device key. Every read, the check and the write
// share one hold of the keychain process lock, the lock SignOutDevice,
// login, signup and the device key rotation write under, so none of them
// can land between the check and the write. opens receives the stored
// device key (Base64) and must not keep it. Its error is returned as is.
func AdoptPersonalDeviceWrappedDEK(store SecretStore, wrapped string, opens func(deviceKeyB64 string) error) (AdoptOutcome, error) {
	outcome := AdoptStored
	err := withPersonalKeyBundleLock(store, func() error {
		binding, _, err := GetAccountBinding(store)
		if err != nil {
			return err
		}
		if binding.SignedOut {
			outcome = AdoptSkippedSignedOut
			return nil
		}
		if err := recoverPersonalKeyBundleLocked(store); err != nil {
			return err
		}
		current, err := getPersonalDeviceWrappedDEKLocked(store)
		if err != nil && !errors.Is(err, ErrSecretNotFound) {
			return err
		}
		if current != "" {
			outcome = AdoptSkippedSlotOccupied
			return nil
		}
		deviceKey, err := getDeviceKeyLocked(store)
		if errors.Is(err, ErrSecretNotFound) || (err == nil && deviceKey == "") {
			return ErrNoDeviceKey
		}
		if err != nil {
			return err
		}
		if err := opens(deviceKey); err != nil {
			return err
		}
		return savePersonalDeviceWrappedDEKLocked(store, wrapped)
	})
	return outcome, err
}
