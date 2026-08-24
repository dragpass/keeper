package keychain

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/dragpass/keeper/config"
)

var errPersonalKeyBundleCleanupPending = errors.New("personal key bundle journal cleanup pending")

type personalKeyBundleJournal struct {
	OldDeviceKeyB64 string `json:"old_device_key_b64"`
	OldWrappedDEK   string `json:"old_wrapped_dek"`
	NewDeviceKeyB64 string `json:"new_device_key_b64"`
	NewWrappedDEK   string `json:"new_wrapped_dek"`
}

func GetPendingPersonalKeyBundle(store SecretStore) (string, error) {
	var value string
	err := withPersonalKeyBundleLock(store, func() error {
		var err error
		value, err = store.Get(config.Service, config.PendingPersonalKeyBundle)
		return err
	})
	return value, err
}

func DeletePendingPersonalKeyBundle(store SecretStore) error {
	return withPersonalKeyBundleLock(store, func() error {
		return store.Delete(config.Service, config.PendingPersonalKeyBundle)
	})
}

func CommitPersonalKeyBundleRotation(
	store SecretStore,
	oldDeviceKeyB64, oldWrappedDEK, newDeviceKeyB64, newWrappedDEK string,
) error {
	return withPersonalKeyBundleLock(store, func() error {
		if err := recoverPersonalKeyBundleLocked(store); err != nil {
			return fmt.Errorf("recover interrupted personal key rotation: %w", err)
		}
		currentDeviceKey, err := getDeviceKeyLocked(store)
		if err != nil {
			return err
		}
		if currentDeviceKey != oldDeviceKeyB64 {
			return errors.New("active device key changed during rotation")
		}
		currentWrappedDEK, err := getPersonalDeviceWrappedDEKLocked(store)
		if err != nil {
			return err
		}
		if currentWrappedDEK != oldWrappedDEK {
			return errors.New("active personal DEK wrap changed during rotation")
		}

		journal := personalKeyBundleJournal{
			OldDeviceKeyB64: oldDeviceKeyB64,
			OldWrappedDEK:   oldWrappedDEK,
			NewDeviceKeyB64: newDeviceKeyB64,
			NewWrappedDEK:   newWrappedDEK,
		}
		rawJournal, err := json.Marshal(journal)
		if err != nil {
			return err
		}
		if err := store.Set(config.Service, config.PendingPersonalKeyBundle, string(rawJournal)); err != nil {
			return err
		}
		if err := saveDeviceKeyLocked(store, newDeviceKeyB64); err != nil {
			return rollbackPersonalKeyBundleLocked(store, err)
		}
		if err := savePersonalDeviceWrappedDEKLocked(store, newWrappedDEK); err != nil {
			return rollbackPersonalKeyBundleLocked(store, err)
		}
		_ = deletePersonalKeyBundleJournalLocked(store)
		return nil
	})
}

func recoverPersonalKeyBundleLocked(store SecretStore) error {
	rawJournal, err := store.Get(config.Service, config.PendingPersonalKeyBundle)
	if errors.Is(err, ErrSecretNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	var journal personalKeyBundleJournal
	if err := json.Unmarshal([]byte(rawJournal), &journal); err != nil {
		return fmt.Errorf("decode personal key rotation journal: %w", err)
	}
	if journal.OldDeviceKeyB64 == "" || journal.OldWrappedDEK == "" ||
		journal.NewDeviceKeyB64 == "" || journal.NewWrappedDEK == "" {
		return errors.New("personal key rotation journal is incomplete")
	}

	deviceKey, deviceErr := getDeviceKeyLocked(store)
	wrappedDEK, wrappedErr := getPersonalDeviceWrappedDEKLocked(store)
	if deviceErr != nil && !errors.Is(deviceErr, ErrSecretNotFound) {
		return deviceErr
	}
	if wrappedErr != nil && !errors.Is(wrappedErr, ErrSecretNotFound) {
		return wrappedErr
	}

	switch {
	case deviceErr == nil && wrappedErr == nil &&
		deviceKey == journal.NewDeviceKeyB64 && wrappedDEK == journal.NewWrappedDEK:
		return deletePersonalKeyBundleJournalLocked(store)
	case deviceErr == nil && wrappedErr == nil &&
		deviceKey == journal.OldDeviceKeyB64 && wrappedDEK == journal.OldWrappedDEK:
		return deletePersonalKeyBundleJournalLocked(store)
	case (errors.Is(deviceErr, ErrSecretNotFound) || deviceKey == journal.OldDeviceKeyB64 || deviceKey == journal.NewDeviceKeyB64) &&
		(errors.Is(wrappedErr, ErrSecretNotFound) || wrappedDEK == journal.OldWrappedDEK || wrappedDEK == journal.NewWrappedDEK):
		if err := saveDeviceKeyLocked(store, journal.OldDeviceKeyB64); err != nil {
			return err
		}
		if err := savePersonalDeviceWrappedDEKLocked(store, journal.OldWrappedDEK); err != nil {
			return err
		}
		return deletePersonalKeyBundleJournalLocked(store)
	default:
		return errors.New("active personal key bundle does not match rotation journal")
	}
}

func deletePersonalKeyBundleJournalLocked(store SecretStore) error {
	if err := store.Delete(config.Service, config.PendingPersonalKeyBundle); err != nil && !errors.Is(err, ErrSecretNotFound) {
		return fmt.Errorf("%w: %v", errPersonalKeyBundleCleanupPending, err)
	}
	return nil
}

func rollbackPersonalKeyBundleLocked(store SecretStore, cause error) error {
	if err := recoverPersonalKeyBundleLocked(store); err != nil {
		return fmt.Errorf("personal key rotation failed: %v; rollback failed: %w", cause, err)
	}
	return cause
}
