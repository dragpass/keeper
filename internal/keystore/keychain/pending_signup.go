package keychain

import (
	"errors"

	"github.com/dragpass/keeper/config"
)

// A signup stages its keypair in the pending slots and its DEK in the pending
// signup DEK slot. The input record next to them lets a retried prepare with
// the same input answer for the staged key instead of replacing it.

func SavePendingSignupPrepareInput(store SecretStore, record string) error {
	return store.Set(config.Service, config.PendingSignupPrepareInput, record)
}

func GetPendingSignupPrepareInput(store SecretStore) (string, error) {
	return store.Get(config.Service, config.PendingSignupPrepareInput)
}

func DeletePendingSignupPrepareInput(store SecretStore) error {
	return store.Delete(config.Service, config.PendingSignupPrepareInput)
}

// StagedSignupKeypair returns the signup keypair in the pending slots, or
// ok=false when there is none. On a device with an active key the pending
// slots belong to a key rotation, never to a signup.
func StagedSignupKeypair(store SecretStore) (privateKey, publicKey string, ok bool, err error) {
	if _, activeErr := GetPrivateKey(store); activeErr == nil {
		return "", "", false, nil
	} else if !errors.Is(activeErr, ErrSecretNotFound) {
		return "", "", false, activeErr
	}
	privateKey, privErr := GetPendingPrivateKey(store)
	publicKey, pubErr := GetPendingPublicKey(store)
	for _, e := range []error{privErr, pubErr} {
		if e != nil && !errors.Is(e, ErrSecretNotFound) {
			return "", "", false, e
		}
	}
	if privErr != nil || pubErr != nil || privateKey == "" || publicKey == "" {
		return "", "", false, nil
	}
	return privateKey, publicKey, true, nil
}

// DiscardPendingSignup drops the staged signup keypair, its DEK and its input
// record, only when the staged public key is the one named and the device has
// no active key. Idempotent.
func DiscardPendingSignup(store SecretStore, publicKey string) (bool, error) {
	_, staged, ok, err := StagedSignupKeypair(store)
	if err != nil || !ok || staged != publicKey {
		return false, err
	}
	for _, drop := range []func(SecretStore) error{
		DeletePendingPrivateKey, DeletePendingPublicKey,
		DeletePendingSignupDeviceWrappedDEK, DeletePendingSignupPrepareInput,
	} {
		if err := drop(store); err != nil && !errors.Is(err, ErrSecretNotFound) {
			return false, err
		}
	}
	return true, nil
}
