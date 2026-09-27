package keychain

import (
	"errors"

	"github.com/dragpass/keeper/config"
)

// A recovery's new account keypair waits in its own pending slots until the
// server accepts it. Until then the active keypair, the session code and every
// other slot stay as they were, so a recovery the server refuses, or one that
// never reaches the server, changes nothing a login depends on.

// ErrSessionCodeUnopened means a key was on hand but none of them opens the
// session code the server sent: the server accepted a key this device does not
// hold, so nothing is promoted.
var ErrSessionCodeUnopened = errors.New("session code does not open with any local key")

// StagePendingRecoveryKeypair replaces the recovery pending slots. A retried
// prepare overwrites only these.
func StagePendingRecoveryKeypair(store SecretStore, privateKey, publicKey string) error {
	return withPersonalKeyBundleLock(store, func() error {
		if err := store.Set(config.Service, config.PendingRecoveryKeeperPrivateKey, privateKey); err != nil {
			return err
		}
		return store.Set(config.Service, config.PendingRecoveryKeeperPublicKey, publicKey)
	})
}

func GetPendingRecoveryPrivateKey(store SecretStore) (string, error) {
	return store.Get(config.Service, config.PendingRecoveryKeeperPrivateKey)
}

func GetPendingRecoveryPublicKey(store SecretStore) (string, error) {
	return store.Get(config.Service, config.PendingRecoveryKeeperPublicKey)
}

func DeletePendingRecoveryPrivateKey(store SecretStore) error {
	return store.Delete(config.Service, config.PendingRecoveryKeeperPrivateKey)
}

func DeletePendingRecoveryPublicKey(store SecretStore) error {
	return store.Delete(config.Service, config.PendingRecoveryKeeperPublicKey)
}

// HasPendingRecoveryKeypair reports a staged recovery the server has not yet
// been seen to accept.
func HasPendingRecoveryKeypair(store SecretStore) (bool, error) {
	var present bool
	err := withPersonalKeyBundleLock(store, func() error {
		_, privErr := GetPendingRecoveryPrivateKey(store)
		_, pubErr := GetPendingRecoveryPublicKey(store)
		if privErr != nil && !errors.Is(privErr, ErrSecretNotFound) {
			return privErr
		}
		if pubErr != nil && !errors.Is(pubErr, ErrSecretNotFound) {
			return pubErr
		}
		present = privErr == nil || pubErr == nil
		return nil
	})
	return present, err
}

// DiscardPendingRecoveryKeypair drops the staged keypair only when it is the
// one whose public key the caller names, so an abort cannot remove a later
// recovery's key. Idempotent.
func DiscardPendingRecoveryKeypair(store SecretStore, publicKey string) (bool, error) {
	var discarded bool
	err := withPersonalKeyBundleLock(store, func() error {
		staged, err := GetPendingRecoveryPublicKey(store)
		if errors.Is(err, ErrSecretNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if staged != publicKey {
			return nil
		}
		if err := DeletePendingRecoveryPrivateKey(store); err != nil && !errors.Is(err, ErrSecretNotFound) {
			return err
		}
		if err := DeletePendingRecoveryPublicKey(store); err != nil && !errors.Is(err, ErrSecretNotFound) {
			return err
		}
		discarded = true
		return nil
	})
	return discarded, err
}

// SessionCodeOpener decrypts the server's session code with one private key
// PEM, or reports that the key does not open it.
type SessionCodeOpener func(privateKeyPEM string) (sessionCode string, opened bool)

// SessionCodeAcceptance says which local key the server's session code was
// encrypted to, and therefore which keypair this save made active.
type SessionCodeAcceptance string

const (
	SessionCodeAcceptedActive   SessionCodeAcceptance = "active"
	SessionCodeAcceptedRecovery SessionCodeAcceptance = "recovery"
	SessionCodeAcceptedSignup   SessionCodeAcceptance = "signup"
)

// AcceptSessionCode stores the server's session code and promotes the pending
// keypair the server accepted. The server encrypts the session code to the
// public key it now holds for the account, so a pending keypair becomes active
// only when the session code opens with it; a stale pending keypair left by an
// abandoned signup or recovery is never promoted by an unrelated save. The
// whole decision runs under the keychain process lock and a repeated save
// finds the promoted key active and changes nothing else.
func AcceptSessionCode(store SecretStore, open SessionCodeOpener) (SessionCodeAcceptance, string, error) {
	var accepted SessionCodeAcceptance
	var sessionCode string
	err := withPersonalKeyBundleLock(store, func() error {
		candidates := 0

		if privateKey, publicKey, ok := readPair(store,
			config.PendingRecoveryKeeperPrivateKey, config.PendingRecoveryKeeperPublicKey); ok {
			candidates++
			if code, opened := open(privateKey); opened {
				if err := activateKeypair(store, privateKey, publicKey, code); err != nil {
					return err
				}
				// A signup DEK still pending belongs to an abandoned signup.
				if err := promotePendingSignupDEKLocked(store, false); err != nil {
					return err
				}
				if err := DeletePendingRecoveryPrivateKey(store); err != nil && !errors.Is(err, ErrSecretNotFound) {
					return err
				}
				if err := DeletePendingRecoveryPublicKey(store); err != nil && !errors.Is(err, ErrSecretNotFound) {
					return err
				}
				accepted, sessionCode = SessionCodeAcceptedRecovery, code
				return nil
			}
		}

		if privateKey, publicKey, ok := readPair(store,
			config.PendingDragPassKeeperPrivateKey, config.PendingDragPassKeeperPublicKey); ok {
			candidates++
			if code, opened := open(privateKey); opened {
				if err := activateKeypair(store, privateKey, publicKey, code); err != nil {
					return err
				}
				if err := promotePendingSignupDEKLocked(store, true); err != nil {
					return err
				}
				_ = DeletePendingPrivateKey(store)
				_ = DeletePendingPublicKey(store)
				accepted, sessionCode = SessionCodeAcceptedSignup, code
				return nil
			}
		}

		if privateKey, err := GetPrivateKey(store); err == nil && privateKey != "" {
			candidates++
			if code, opened := open(privateKey); opened {
				if err := promotePendingSignupDEKLocked(store, false); err != nil {
					return err
				}
				if err := SaveSessionCode(store, code); err != nil {
					return err
				}
				accepted, sessionCode = SessionCodeAcceptedActive, code
				return nil
			}
		} else if err != nil && !errors.Is(err, ErrSecretNotFound) {
			return err
		}

		if candidates == 0 {
			return ErrSecretNotFound
		}
		return ErrSessionCodeUnopened
	})
	return accepted, sessionCode, err
}

func readPair(store SecretStore, privateSlot, publicSlot string) (string, string, bool) {
	privateKey, privErr := store.Get(config.Service, privateSlot)
	publicKey, pubErr := store.Get(config.Service, publicSlot)
	if privErr != nil || pubErr != nil || privateKey == "" || publicKey == "" {
		return "", "", false
	}
	return privateKey, publicKey, true
}

// activateKeypair writes the session code last: a crash before it leaves the
// pending slot in place, and the retried save opens it again and finishes.
func activateKeypair(store SecretStore, privateKey, publicKey, sessionCode string) error {
	if err := SavePrivateKey(store, privateKey); err != nil {
		return err
	}
	if err := SavePublicKey(store, publicKey); err != nil {
		return err
	}
	return SaveSessionCode(store, sessionCode)
}

// StagedAccountKeypair is an account keypair a recovery or a signup staged
// and save_session_code has not promoted.
type StagedAccountKeypair struct {
	Stage      SessionCodeAcceptance
	PrivateKey string
	PublicKey  string
}

// StagedAccountKeypairs reads the staged keypairs, the recovery one first:
// on one device a recovery is always the later of the two, since signup
// refuses a registered device. It only reads.
func StagedAccountKeypairs(store SecretStore) ([]StagedAccountKeypair, error) {
	var staged []StagedAccountKeypair
	err := withPersonalKeyBundleLock(store, func() error {
		slots := []struct {
			stage                   SessionCodeAcceptance
			privateSlot, publicSlot string
		}{
			{SessionCodeAcceptedRecovery, config.PendingRecoveryKeeperPrivateKey, config.PendingRecoveryKeeperPublicKey},
			{SessionCodeAcceptedSignup, config.PendingDragPassKeeperPrivateKey, config.PendingDragPassKeeperPublicKey},
		}
		for _, slot := range slots {
			if privateKey, publicKey, ok := readPair(store, slot.privateSlot, slot.publicSlot); ok {
				staged = append(staged, StagedAccountKeypair{Stage: slot.stage, PrivateKey: privateKey, PublicKey: publicKey})
			}
		}
		return nil
	})
	return staged, err
}
