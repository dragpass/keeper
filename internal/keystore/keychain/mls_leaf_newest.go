package keychain

// mls_leaf_newest.go — the newest MLS leaf declaration an owner has accepted
// for each peer account.
//
//	mls-leaf-newest:<owner>:<account> → {"v":1,"not_before":…,"fingerprint":…}
//
// A declaration embedded in a leaf is checked against the account key, not
// against the directory, so a declaration the account has since superseded
// still verifies: its signature is as good as the day it was made. Whoever
// holds a retired device's leaf key can keep minting KeyPackages around it.
// This record is the part of the answer a device can give on its own — once it
// has accepted a newer declaration for an account, an older one is refused.
// A device that never saw the newer one is not protected by it.
//
// Per account, not per device, because that is the rule: at most one leaf key
// is current for an account at a time.

import (
	"bytes"
	"encoding/json"
	"errors"

	"github.com/dragpass/keeper/config"
)

const MLSLeafNewestVersion = 1

// MLSLeafNewest is the stored record. NotBefore is the declaration's
// not_before (Unix seconds); Fingerprint is its signature key fingerprint,
// which is what tells two declarations with the same not_before apart.
type MLSLeafNewest struct {
	V           int    `json:"v"`
	NotBefore   int64  `json:"not_before"`
	Fingerprint string `json:"fingerprint"`
}

func MLSLeafNewestAccount(ownerAccountID, peerAccountID string) string {
	return config.MLSLeafNewestPrefix + ownerAccountID + ":" + peerAccountID
}

// GetMLSLeafNewest reports false when this owner has accepted no declaration
// for the account yet.
func GetMLSLeafNewest(store SecretStore, ownerAccountID, peerAccountID string) (MLSLeafNewest, bool, error) {
	raw, err := store.Get(config.Service, MLSLeafNewestAccount(ownerAccountID, peerAccountID))
	if err != nil {
		if errors.Is(err, ErrSecretNotFound) {
			return MLSLeafNewest{}, false, nil
		}
		return MLSLeafNewest{}, false, err
	}
	var rec MLSLeafNewest
	dec := json.NewDecoder(bytes.NewReader([]byte(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rec); err != nil || dec.More() {
		return MLSLeafNewest{}, false, errors.New("mls leaf newest record is not readable")
	}
	if rec.V != MLSLeafNewestVersion || rec.NotBefore <= 0 || rec.Fingerprint == "" {
		return MLSLeafNewest{}, false, errors.New("mls leaf newest record is malformed")
	}
	return rec, true, nil
}

func SaveMLSLeafNewest(store SecretStore, ownerAccountID, peerAccountID string, rec MLSLeafNewest) error {
	rec.V = MLSLeafNewestVersion
	if rec.NotBefore <= 0 || rec.Fingerprint == "" {
		return errors.New("mls leaf newest record is malformed")
	}
	encoded, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	return store.Set(config.Service, MLSLeafNewestAccount(ownerAccountID, peerAccountID), string(encoded))
}
