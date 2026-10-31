package keychain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/dragpass/keeper/config"
)

const personalDEKProvenanceSlot = "personal_dek_provenance_v1"

var ErrPersonalDEKProvenance = errors.New("personal DEK provenance unavailable")

// PersonalDEKProvenance is local evidence, not permission to decrypt. Every
// display still needs a separate, current online authorization decision.
type PersonalDEKProvenance struct {
	Version              int    `json:"v"`
	AccountID            string `json:"account_id"`
	DeviceID             string `json:"device_id"`
	TokenID              string `json:"token_id"`
	SessionIssuedAtNanos int64  `json:"session_issued_at_nanos,string"`
	LoginGeneration      string `json:"login_generation"`
	BindingGeneration    uint64 `json:"binding_generation"`
	ServerWrapDigest     string `json:"server_wrap_digest"`
	DeviceWrapDigest     string `json:"device_wrap_digest"`
	DeviceKeyDigest      string `json:"device_key_digest"`
}

// BindPersonalDEKProvenance accepts only a handler-verified server assertion.
// verify compares already-opened server material to the current device slot;
// it must not perform PBKDF2, network I/O or reenter the keychain lock.
func BindPersonalDEKProvenance(store SecretStore, proof PersonalDEKProvenance, verify func(deviceKey, wrapped string) error) error {
	return withPersonalKeyBundleLock(store, func() error {
		if err := recoverPersonalKeyBundleLocked(store); err != nil {
			return err
		}
		binding, _, err := GetAccountBinding(store)
		if err != nil {
			return err
		}
		proof.BindingGeneration = binding.Generation
		if err := checkPersonalProvenanceIdentity(store, proof); err != nil {
			return err
		}
		wrapped, err := getPersonalDeviceWrappedDEKLocked(store)
		if err != nil {
			return err
		}
		deviceKey, err := getDeviceKeyLocked(store)
		if err != nil {
			return err
		}
		if verify == nil || wrapped == "" || deviceKey == "" {
			return ErrPersonalDEKProvenance
		}
		if err := verify(deviceKey, wrapped); err != nil {
			return err
		}
		previous, readErr := store.Get(config.Service, personalDEKProvenanceSlot)
		if readErr != nil && !errors.Is(readErr, ErrSecretNotFound) {
			return readErr
		}
		if readErr == nil {
			var prior PersonalDEKProvenance
			if json.Unmarshal([]byte(previous), &prior) != nil || prior.Version != 1 {
				return ErrPersonalDEKProvenance
			}
			if prior.LoginGeneration == proof.LoginGeneration && prior.SessionIssuedAtNanos != proof.SessionIssuedAtNanos {
				return ErrPersonalDEKProvenance
			}
		}
		proof.Version = 1
		proof.DeviceWrapDigest = personalBindingDigest(wrapped)
		proof.DeviceKeyDigest = personalBindingDigest(deviceKey)
		encoded, err := json.Marshal(proof)
		if err != nil {
			return err
		}
		return store.Set(config.Service, personalDEKProvenanceSlot, string(encoded))
	})
}

// ReadPersonalDEKProvenance never upgrades an old slot. All comparisons are
// under the same lock as slot writes, login commits and device sign-out.
func ReadPersonalDEKProvenance(store SecretStore) (PersonalDEKProvenance, error) {
	var record PersonalDEKProvenance
	err := withPersonalKeyBundleLock(store, func() error {
		if err := recoverPersonalKeyBundleLocked(store); err != nil {
			return err
		}
		raw, err := store.Get(config.Service, personalDEKProvenanceSlot)
		if err != nil {
			return err
		}
		if err := json.Unmarshal([]byte(raw), &record); err != nil {
			return err
		}
		if record.Version != 1 || record.TokenID == "" || record.SessionIssuedAtNanos <= 0 || len(record.ServerWrapDigest) != 64 {
			return ErrPersonalDEKProvenance
		}
		if err := checkPersonalProvenanceIdentity(store, record); err != nil {
			return err
		}
		wrapped, err := getPersonalDeviceWrappedDEKLocked(store)
		if err != nil {
			return err
		}
		deviceKey, err := getDeviceKeyLocked(store)
		if err != nil {
			return err
		}
		if wrapped == "" || deviceKey == "" || record.DeviceWrapDigest != personalBindingDigest(wrapped) || record.DeviceKeyDigest != personalBindingDigest(deviceKey) {
			return ErrPersonalDEKProvenance
		}
		return nil
	})
	if err != nil {
		return PersonalDEKProvenance{}, err
	}
	return record, nil
}

func checkPersonalProvenanceIdentity(store SecretStore, record PersonalDEKProvenance) error {
	binding, found, err := GetAccountBinding(store)
	if err != nil {
		return err
	}
	if !found || binding.SignedOut || binding.Generation == 0 || binding.Generation != record.BindingGeneration || binding.AccountID != record.AccountID {
		return ErrPersonalDEKProvenance
	}
	device, found, err := GetDeviceID(store)
	if err != nil {
		return err
	}
	if !found || device != record.DeviceID {
		return ErrPersonalDEKProvenance
	}
	login, err := ReadChatLogin(store)
	if err != nil {
		return err
	}
	if login.Committing || login.Generation == "" || login.Generation != record.LoginGeneration || login.AccountID != record.AccountID {
		return ErrPersonalDEKProvenance
	}
	return nil
}

func personalBindingDigest(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}
