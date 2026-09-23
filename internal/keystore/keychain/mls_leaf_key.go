package keychain

// mls_leaf_key.go — this device's MLS leaf signature key.
//
// One record under config.Service:
//
//	mls_leaf_signature_key → {"v":1,"account_id":…,"device_id":…,"secret_key":…,"public_key":…}
//
// The key and the identity it was declared for are stored together because a
// session built from one and not the other would sign as a leaf whose
// credential no declaration vouches for. secret_key is the 64-byte Ed25519
// keypair (seed || public) — the layout crypto/ed25519 and mls-rs's
// SigningKey::from_keypair_bytes both use — so it reaches the MLS library
// without conversion.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"

	"github.com/dragpass/keeper/config"
	"github.com/dragpass/keeper/internal/keystore/secure"
)

const MLSLeafKeyVersion = 1

// MLSLeafKey is the decoded record. SecretKey is the caller's to wipe.
type MLSLeafKey struct {
	V         int    `json:"v"`
	AccountID string `json:"account_id"`
	DeviceID  string `json:"device_id"`
	SecretKey []byte `json:"secret_key"`
	PublicKey []byte `json:"public_key"`
}

// GetMLSLeafKey reads the record. Absence is reported by the bool, not as an
// error: a device that has never enrolled is the ordinary first state.
func GetMLSLeafKey(store SecretStore) (MLSLeafKey, bool, error) {
	raw, err := store.Get(config.Service, config.MLSLeafSignatureKey)
	if err != nil {
		if errors.Is(err, ErrSecretNotFound) {
			return MLSLeafKey{}, false, nil
		}
		return MLSLeafKey{}, false, err
	}
	defer secure.WipeString(&raw)

	var key MLSLeafKey
	if err := json.Unmarshal([]byte(raw), &key); err != nil {
		return MLSLeafKey{}, false, errors.New("mls leaf key record is not readable")
	}
	if err := key.check(); err != nil {
		secure.Zeroize(key.SecretKey)
		return MLSLeafKey{}, false, err
	}
	return key, true, nil
}

// SaveMLSLeafKey overwrites the record. Replacing it is how a rotation
// discards the old key; there is no second slot for it to survive in.
func SaveMLSLeafKey(store SecretStore, key MLSLeafKey) error {
	key.V = MLSLeafKeyVersion
	if err := key.check(); err != nil {
		return err
	}
	encoded, err := json.Marshal(key)
	if err != nil {
		return err
	}
	defer secure.Zeroize(encoded)
	return store.Set(config.Service, config.MLSLeafSignatureKey, string(encoded))
}

// DeleteMLSLeafKey is idempotent: the bool reports whether a record was there.
func DeleteMLSLeafKey(store SecretStore) (bool, error) {
	if err := store.Delete(config.Service, config.MLSLeafSignatureKey); err != nil {
		if errors.Is(err, ErrSecretNotFound) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// check never names a field's value: the record holds a private key.
func (k MLSLeafKey) check() error {
	if k.V != MLSLeafKeyVersion {
		return errors.New("mls leaf key record has an unknown version")
	}
	if k.AccountID == "" || k.DeviceID == "" {
		return errors.New("mls leaf key record names no account or device")
	}
	if len(k.SecretKey) != ed25519.PrivateKeySize || len(k.PublicKey) != ed25519.PublicKeySize {
		return errors.New("mls leaf key record has a key of the wrong size")
	}
	if !bytes.Equal(k.SecretKey[ed25519.SeedSize:], k.PublicKey) {
		return errors.New("mls leaf key record's public key is not its secret key's")
	}
	return nil
}
