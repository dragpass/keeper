package keychain

// mls_leaf_key.go — this device's MLS leaf signature key, active and pending.
//
// Two records under config.Service, same layout:
//
//	mls_leaf_signature_key         → {"v":3,"account_id":…,"device_id":…,"secret_key":…,"public_key":…,"declaration":…}
//	mls_leaf_signature_key_pending → the same, for a key ariadne has not accepted yet
//
// The key, the identity it was declared for, and the declaration itself are
// stored together because a session built from one and not the others would
// sign as a leaf whose credential no declaration vouches for. The declaration
// is kept rather than re-signed on demand because re-signing needs the account
// key and a fresh server challenge, and every KeyPackage embeds it.
//
// Only the active record is ever embedded or signs anything in MLS. The pending
// one exists so that a declaration the server may or may not have accepted
// never replaces what peers already hold: mls_leaf_declare writes pending,
// mls_leaf_promote copies it over active once ariadne's signed acceptance names
// it.
//
// Only version 3 reads. The v1 and v2 records of unreleased development builds
// are unreadable like any other foreign record, and reset_device_identity
// clears them. secret_key is the 64-byte Ed25519 keypair (seed || public) —
// the layout crypto/ed25519 and mls-rs's SigningKey::from_keypair_bytes both
// use — so it reaches the MLS library without conversion.
//
// None of these helpers take a lock. The handlers that read and write the
// records hold WithMLSLeafLock across the whole read → mint → sign → save
// section, and that lock is not reentrant.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"

	"github.com/dragpass/keeper/config"
	"github.com/dragpass/keeper/internal/keystore/secure"
)

const (
	MLSLeafKeyVersion = 3

	// MLSLeafDeclarationMaxBytes bounds the stored declaration payload. Kept
	// equal to proto.MLSLeafExtensionMaxBytes by a test in the handlers
	// package; this package does not import proto.
	MLSLeafDeclarationMaxBytes = 8192
)

// MLSLeafKey is the decoded record. SecretKey is the caller's to wipe.
//
// Declaration is the key's leaf declaration extension payload
// (proto.EncodeMLSLeafExtension), stored as the bytes a KeyPackage embeds so
// that what peers see is exactly what was signed.
type MLSLeafKey struct {
	V           int    `json:"v"`
	AccountID   string `json:"account_id"`
	DeviceID    string `json:"device_id"`
	SecretKey   []byte `json:"secret_key"`
	PublicKey   []byte `json:"public_key"`
	Declaration []byte `json:"declaration,omitempty"`
}

// WithMLSLeafLock runs fn under the lock the personal key bundle already uses:
// an in-process mutex in front of a cross-process file lock. Keeper runs one
// process per native-messaging connection, so two declares at once are two
// processes, and only the file half keeps them from each minting a key.
//
// The in-process half is a plain sync.Mutex and is not reentrant. fn must not
// call anything that takes this lock again — the device key and personal DEK
// helpers do — or the process deadlocks.
func WithMLSLeafLock(store SecretStore, fn func() error) error {
	return withPersonalKeyBundleLock(store, fn)
}

// GetMLSLeafKey reads the active record. Absence is reported by the bool, not
// as an error: a device that has never enrolled is the ordinary first state.
func GetMLSLeafKey(store SecretStore) (MLSLeafKey, bool, error) {
	return getMLSLeafRecord(store, config.MLSLeafSignatureKey)
}

// GetMLSLeafPending reads the pending record.
func GetMLSLeafPending(store SecretStore) (MLSLeafKey, bool, error) {
	return getMLSLeafRecord(store, config.MLSLeafSignatureKeyPending)
}

func getMLSLeafRecord(store SecretStore, account string) (MLSLeafKey, bool, error) {
	raw, err := store.Get(config.Service, account)
	if err != nil {
		if errors.Is(err, ErrSecretNotFound) {
			return MLSLeafKey{}, false, nil
		}
		return MLSLeafKey{}, false, err
	}
	defer secure.WipeString(&raw)

	// Strict: a field this version does not know, or bytes after the object,
	// mean the record is not one this code wrote.
	var key MLSLeafKey
	dec := json.NewDecoder(bytes.NewReader([]byte(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&key); err != nil || dec.More() {
		secure.Zeroize(key.SecretKey)
		return MLSLeafKey{}, false, errors.New("mls leaf key record is not readable")
	}
	if err := key.check(); err != nil {
		secure.Zeroize(key.SecretKey)
		return MLSLeafKey{}, false, err
	}
	return key, true, nil
}

// SaveMLSLeafKey overwrites the active record. Promotion is this one write:
// the key and its declaration replace the old pair together or not at all.
func SaveMLSLeafKey(store SecretStore, key MLSLeafKey) error {
	return saveMLSLeafRecord(store, config.MLSLeafSignatureKey, key)
}

func SaveMLSLeafPending(store SecretStore, key MLSLeafKey) error {
	return saveMLSLeafRecord(store, config.MLSLeafSignatureKeyPending, key)
}

func saveMLSLeafRecord(store SecretStore, account string, key MLSLeafKey) error {
	key.V = MLSLeafKeyVersion
	if err := key.check(); err != nil {
		return err
	}
	encoded, err := json.Marshal(key)
	if err != nil {
		return err
	}
	defer secure.Zeroize(encoded)
	return store.Set(config.Service, account, string(encoded))
}

// DeleteMLSLeafKey is idempotent: the bool reports whether a record was there.
func DeleteMLSLeafKey(store SecretStore) (bool, error) {
	return deleteMLSLeafRecord(store, config.MLSLeafSignatureKey)
}

func DeleteMLSLeafPending(store SecretStore) (bool, error) {
	return deleteMLSLeafRecord(store, config.MLSLeafSignatureKeyPending)
}

func deleteMLSLeafRecord(store SecretStore, account string) (bool, error) {
	if err := store.Delete(config.Service, account); err != nil {
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
	if err := k.checkDeclarationSize(); err != nil {
		return err
	}
	return k.checkKey()
}

func (k MLSLeafKey) checkDeclarationSize() error {
	if len(k.Declaration) == 0 || len(k.Declaration) > MLSLeafDeclarationMaxBytes {
		return errors.New("mls leaf key record has no declaration or one of the wrong size")
	}
	return nil
}

func (k MLSLeafKey) checkKey() error {
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
