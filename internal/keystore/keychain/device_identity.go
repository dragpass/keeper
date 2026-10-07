package keychain

// device_identity.go — the machine's device id and the account binding hint.
//
//	device_id       → a lowercase UUID, written once
//	account_binding → {"v":1,"account_id":…,"alias":…,"generation":…,"signed_out":…}
//
// Neither is a secret. Both are written under the keychain process lock, the
// same lock the device key, the personal DEK and the MLS leaf records use, so
// two Keeper processes (one per Native Messaging connection, plus the local
// RPC owner) never each write their own value. The lock is not reentrant:
// nothing here calls a helper that takes it again.

import (
	"bytes"
	"encoding/json"
	"errors"

	"github.com/dragpass/keeper/config"
	"github.com/dragpass/keeper/internal/keystore/secure"
)

// DeviceIDSource says where device_id_ensure took the id from.
type DeviceIDSource string

const (
	DeviceIDStored    DeviceIDSource = "stored"
	DeviceIDLeaf      DeviceIDSource = "leaf"
	DeviceIDCandidate DeviceIDSource = "candidate"
	DeviceIDGenerated DeviceIDSource = "generated"
)

// ErrInvalidDeviceID reports a stored device id, or one an MLS leaf record
// names, that is not a lowercase UUID. It is never repaired: replacing it
// would silently move this machine to another server device.
var ErrInvalidDeviceID = errors.New("stored device id is invalid")

// ErrInvalidAccountBinding reports an account binding record this code did
// not write. Only reset_device_identity removes it.
var ErrInvalidAccountBinding = errors.New("stored account binding is invalid")

// ErrUnreadableLeaf reports an MLS leaf record that exists but cannot be
// read while the device id is being chosen. The id it names is unknown, and
// picking another one could strand the leaf, so the choice is refused.
var ErrUnreadableLeaf = errors.New("mls leaf record is not readable")

// GetDeviceID reads the device id without the lock: one Get is atomic, and
// the slot is written once.
func GetDeviceID(store SecretStore) (string, bool, error) {
	id, err := store.Get(config.Service, config.DeviceID)
	if errors.Is(err, ErrSecretNotFound) || (err == nil && id == "") {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	if !ValidDeviceID(id) {
		return "", false, ErrInvalidDeviceID
	}
	return id, true, nil
}

// EnsureDeviceID returns the stored device id, or chooses and stores one:
// the device id of the active MLS leaf record, else of the pending one, else
// what fallback returns. The read, the choice and the write share the
// keychain process lock, so concurrent callers in one or several processes
// store one id. An existing id is never replaced.
func EnsureDeviceID(store SecretStore, fallback func() (string, DeviceIDSource, error)) (string, DeviceIDSource, error) {
	var (
		id     string
		source DeviceIDSource
	)
	err := withPersonalKeyBundleLock(store, func() error {
		stored, found, err := GetDeviceID(store)
		if err != nil {
			return err
		}
		if found {
			id, source = stored, DeviceIDStored
			return nil
		}
		leafID, err := leafDeviceID(store)
		if err != nil {
			return err
		}
		if leafID != "" {
			id, source = leafID, DeviceIDLeaf
		} else if id, source, err = fallback(); err != nil {
			return err
		}
		if !ValidDeviceID(id) {
			return ErrInvalidDeviceID
		}
		return store.Set(config.Service, config.DeviceID, id)
	})
	if err != nil {
		return "", "", err
	}
	return id, source, nil
}

// leafDeviceID is the device id the active leaf record names, else the
// pending one's, else "". The caller holds the lock.
func leafDeviceID(store SecretStore) (string, error) {
	for _, get := range []func(SecretStore) (MLSLeafKey, bool, error){GetMLSLeafKey, GetMLSLeafPending} {
		key, found, err := get(store)
		secure.Zeroize(key.SecretKey)
		if err != nil {
			return "", ErrUnreadableLeaf
		}
		if !found {
			continue
		}
		if !ValidDeviceID(key.DeviceID) {
			return "", ErrInvalidDeviceID
		}
		return key.DeviceID, nil
	}
	return "", nil
}

// DeleteDeviceID is idempotent.
func DeleteDeviceID(store SecretStore) error {
	return withPersonalKeyBundleLock(store, func() error {
		err := store.Delete(config.Service, config.DeviceID)
		if errors.Is(err, ErrSecretNotFound) {
			return nil
		}
		return err
	})
}

// ValidDeviceID accepts a lowercase hyphenated UUID other than the nil UUID,
// the form proto requires of every device_id. Version and variant nibbles are
// not pinned, as there.
func ValidDeviceID(value string) bool {
	if len(value) != 36 {
		return false
	}
	nonZero := false
	for i := 0; i < len(value); i++ {
		c := value[i]
		switch {
		case i == 8 || i == 13 || i == 18 || i == 23:
			if c != '-' {
				return false
			}
		case c >= '0' && c <= '9':
			nonZero = nonZero || c != '0'
		case c >= 'a' && c <= 'f':
			nonZero = true
		default:
			return false
		}
	}
	return nonZero
}

const accountBindingVersion = 1

// AccountBinding is the decoded account binding record. Generation moves on
// every change and every renewal, so a reader that polls it sees any change,
// signed_out included.
type AccountBinding struct {
	V          int    `json:"v"`
	AccountID  string `json:"account_id"`
	Alias      string `json:"alias"`
	Generation uint64 `json:"generation"`
	SignedOut  bool   `json:"signed_out"`
}

// GetAccountBinding reads the record without the lock. Absence is the bool.
func GetAccountBinding(store SecretStore) (AccountBinding, bool, error) {
	raw, err := store.Get(config.Service, config.AccountBinding)
	if errors.Is(err, ErrSecretNotFound) || (err == nil && raw == "") {
		return AccountBinding{}, false, nil
	}
	if err != nil {
		return AccountBinding{}, false, err
	}
	var binding AccountBinding
	dec := json.NewDecoder(bytes.NewReader([]byte(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&binding); err != nil || dec.More() || binding.V != accountBindingVersion {
		return AccountBinding{}, false, ErrInvalidAccountBinding
	}
	return binding, true, nil
}

// SetAccountBinding records the account the App signed in to. A record that
// already says exactly this, and is not signed out, is left as it is unless
// renew is set; anything else is replaced with the next generation and
// signed_out false. renew is the App's word that it has just opened a
// session: a recovery that rotated the account key or a sign-in that
// re-registered a revoked device leaves the account and alias as they were,
// and the Extension, which waits for the generation to move before it
// retries a refused sign-in, must still see it. changed reports whether it
// wrote.
func SetAccountBinding(store SecretStore, accountID, alias string, renew bool) (AccountBinding, bool, error) {
	var (
		result  AccountBinding
		changed bool
	)
	err := withPersonalKeyBundleLock(store, func() error {
		current, _, err := GetAccountBinding(store)
		if err != nil {
			return err
		}
		if !renew && current.AccountID == accountID && current.Alias == alias && !current.SignedOut && current.Generation > 0 {
			result = current
			return nil
		}
		next := AccountBinding{
			V: accountBindingVersion, AccountID: accountID, Alias: alias,
			Generation: current.Generation + 1,
		}
		if err := saveAccountBinding(store, next); err != nil {
			return err
		}
		result, changed = next, true
		return nil
	})
	return result, changed, err
}

// SignOutDevice deletes the device-wrapped personal DEK (the device master)
// and marks the binding signed out, in one hold of the lock, so another
// process never sees the DEK gone while the binding still says signed in, or
// the reverse. Nothing else is touched: the account key, the device key, the
// request key, the MLS leaf and the pins stay. removed reports whether a
// device master was there. A device with no binding gets a record that is
// only signed out, so a later status still says so.
func SignOutDevice(store SecretStore) (bool, AccountBinding, error) {
	var (
		removed bool
		result  AccountBinding
	)
	err := withPersonalKeyBundleLock(store, func() error {
		current, _, err := GetAccountBinding(store)
		if err != nil {
			return err
		}
		if err := recoverPersonalKeyBundleLocked(store); err != nil {
			return err
		}
		wrapped, err := getPersonalDeviceWrappedDEKLocked(store)
		switch {
		case errors.Is(err, ErrSecretNotFound):
		case err != nil:
			return err
		default:
			removed = wrapped != ""
			if err := store.Delete(config.Service, config.PersonalDeviceWrappedDEK); err != nil && !errors.Is(err, ErrSecretNotFound) {
				return err
			}
		}
		if current.SignedOut && current.Generation > 0 {
			result = current
			return nil
		}
		current.V = accountBindingVersion
		current.Generation++
		current.SignedOut = true
		if err := saveAccountBinding(store, current); err != nil {
			return err
		}
		result = current
		return nil
	})
	return removed, result, err
}

// SignOutAccountBinding marks the binding signed out with the next
// generation and touches nothing else: the device master, the account key
// and every other slot stay. A binding already signed out is left as it is
// (changed false). A device with no binding gets a record that is only
// signed out, as SignOutDevice does.
func SignOutAccountBinding(store SecretStore) (AccountBinding, bool, error) {
	var (
		result  AccountBinding
		changed bool
	)
	err := withPersonalKeyBundleLock(store, func() error {
		current, _, err := GetAccountBinding(store)
		if err != nil {
			return err
		}
		if current.SignedOut && current.Generation > 0 {
			result = current
			return nil
		}
		current.V = accountBindingVersion
		current.Generation++
		current.SignedOut = true
		if err := saveAccountBinding(store, current); err != nil {
			return err
		}
		result, changed = current, true
		return nil
	})
	return result, changed, err
}

// DeleteAccountBinding is idempotent.
func DeleteAccountBinding(store SecretStore) error {
	return withPersonalKeyBundleLock(store, func() error {
		err := store.Delete(config.Service, config.AccountBinding)
		if errors.Is(err, ErrSecretNotFound) {
			return nil
		}
		return err
	})
}

func saveAccountBinding(store SecretStore, binding AccountBinding) error {
	encoded, err := json.Marshal(binding)
	if err != nil {
		return err
	}
	return store.Set(config.Service, config.AccountBinding, string(encoded))
}
