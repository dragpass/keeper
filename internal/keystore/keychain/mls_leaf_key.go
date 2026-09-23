package keychain

// mls_leaf_key.go — this device's MLS leaf signature key.
//
// One record under config.Service:
//
//	mls_leaf_signature_key → {"v":2,"account_id":…,"device_id":…,"secret_key":…,"public_key":…,"declaration":…}
//
// The key, the identity it was declared for, and the declaration itself are
// stored together because a session built from one and not the others would
// sign as a leaf whose credential no declaration vouches for. The declaration
// is kept rather than re-signed on demand because re-signing needs the account
// key and a fresh server challenge, and every KeyPackage embeds it.
//
// This is the *active* key and its declaration: the one every KeyPackage and
// every new group carries. A record written by 0.0.43 (v1) has no declaration;
// it still reads, and an `enroll` for the same identity upgrades it. secret_key is the 64-byte Ed25519
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

const (
	MLSLeafKeyVersion = 2

	// mlsLeafKeyVersionWithoutDeclaration is what 0.0.43 wrote.
	mlsLeafKeyVersionWithoutDeclaration = 1

	// MLSLeafDeclarationMaxBytes bounds the stored declaration payload. Kept
	// equal to proto.MLSLeafExtensionMaxBytes by a test in the handlers
	// package; this package does not import proto.
	MLSLeafDeclarationMaxBytes = 8192
)

// MLSLeafKey is the decoded record. SecretKey is the caller's to wipe.
//
// Declaration is the active key's leaf declaration extension payload
// (proto.EncodeMLSLeafExtension), stored as the bytes a KeyPackage embeds so
// that what peers see is exactly what was signed. Nil only for a v1 record.
type MLSLeafKey struct {
	V           int    `json:"v"`
	AccountID   string `json:"account_id"`
	DeviceID    string `json:"device_id"`
	SecretKey   []byte `json:"secret_key"`
	PublicKey   []byte `json:"public_key"`
	Declaration []byte `json:"declaration,omitempty"`
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

	// Strict: a field this version does not know, or bytes after the object,
	// mean the record is not one this code wrote.
	var key MLSLeafKey
	dec := json.NewDecoder(bytes.NewReader([]byte(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&key); err != nil || dec.More() {
		secure.Zeroize(key.SecretKey)
		return MLSLeafKey{}, false, errors.New("mls leaf key record is not readable")
	}
	if err := key.checkStored(); err != nil {
		secure.Zeroize(key.SecretKey)
		return MLSLeafKey{}, false, err
	}
	return key, true, nil
}

// SaveMLSLeafKey overwrites the record with a key and its declaration. The two
// are one write, so a rotation replaces both or neither, and there is no
// second slot for the old key to survive in.
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

// checkStored accepts a v1 record, which carries no declaration, as well as
// the current one.
func (k MLSLeafKey) checkStored() error {
	if k.V == mlsLeafKeyVersionWithoutDeclaration {
		if k.Declaration != nil {
			return errors.New("mls leaf key record has a declaration its version cannot carry")
		}
		return k.checkKey()
	}
	return k.check()
}

// check never names a field's value: the record holds a private key.
func (k MLSLeafKey) check() error {
	if k.V != MLSLeafKeyVersion {
		return errors.New("mls leaf key record has an unknown version")
	}
	if len(k.Declaration) == 0 || len(k.Declaration) > MLSLeafDeclarationMaxBytes {
		return errors.New("mls leaf key record has no declaration or one of the wrong size")
	}
	return k.checkKey()
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
