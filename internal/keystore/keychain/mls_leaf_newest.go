package keychain

// mls_leaf_newest.go — the newest MLS leaf declaration an owner has accepted
// for each peer account.
//
//	mls-leaf-newest:<owner>:<account> → {"v":2,"not_before":…,"fingerprint":…,"first_seen_at":…}
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
//
// first_seen_at (version 2, 0.0.48) is when this owner's Keeper clock first
// accepted the recorded declaration. It starts the grace period after which a
// leaf a Welcome's tree still holds under an older declaration is refused.

import (
	"bytes"
	"encoding/json"
	"errors"

	"github.com/dragpass/keeper/config"
)

const (
	MLSLeafNewestVersion = 2

	// mlsLeafNewestLegacyVersion is what 0.0.44–0.0.47 wrote: no first_seen_at.
	mlsLeafNewestLegacyVersion = 1
)

// MLSLeafNewest is the stored record. NotBefore is the declaration's
// not_before (Unix seconds); Fingerprint is its signature key fingerprint,
// which is what tells two declarations with the same not_before apart.
// FirstSeenAt is the Keeper clock (Unix seconds) when the record moved to this
// declaration; seeing the same declaration again does not change it. It is zero
// only in a record read back from a version 1 write, which never had one — the
// reader decides what that means, because only the reader has a clock.
type MLSLeafNewest struct {
	V           int    `json:"v"`
	NotBefore   int64  `json:"not_before"`
	Fingerprint string `json:"fingerprint"`
	FirstSeenAt int64  `json:"first_seen_at,omitempty"`
}

// SameDeclaration compares the declaration a record names, not when it was seen.
func (r MLSLeafNewest) SameDeclaration(o MLSLeafNewest) bool {
	return r.NotBefore == o.NotBefore && r.Fingerprint == o.Fingerprint
}

func MLSLeafNewestAccount(ownerAccountID, peerAccountID string) string {
	return config.MLSLeafNewestPrefix + ownerAccountID + ":" + peerAccountID
}

// GetMLSLeafNewest reports false when this owner has accepted no declaration
// for the account yet. A version 1 record comes back with FirstSeenAt zero; a
// version 1 record that carries first_seen_at, or a version 2 record without a
// positive one, is malformed.
func GetMLSLeafNewest(store SecretStore, ownerAccountID, peerAccountID string) (MLSLeafNewest, bool, error) {
	raw, err := store.Get(config.Service, MLSLeafNewestAccount(ownerAccountID, peerAccountID))
	if err != nil {
		if errors.Is(err, ErrSecretNotFound) {
			return MLSLeafNewest{}, false, nil
		}
		return MLSLeafNewest{}, false, err
	}
	var rec struct {
		V           int    `json:"v"`
		NotBefore   int64  `json:"not_before"`
		Fingerprint string `json:"fingerprint"`
		FirstSeenAt *int64 `json:"first_seen_at"`
	}
	dec := json.NewDecoder(bytes.NewReader([]byte(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rec); err != nil || dec.More() {
		return MLSLeafNewest{}, false, errors.New("mls leaf newest record is not readable")
	}
	if rec.NotBefore <= 0 || rec.Fingerprint == "" {
		return MLSLeafNewest{}, false, errors.New("mls leaf newest record is malformed")
	}
	out := MLSLeafNewest{V: rec.V, NotBefore: rec.NotBefore, Fingerprint: rec.Fingerprint}
	switch {
	case rec.V == mlsLeafNewestLegacyVersion && rec.FirstSeenAt == nil:
	case rec.V == MLSLeafNewestVersion && rec.FirstSeenAt != nil && *rec.FirstSeenAt > 0:
		out.FirstSeenAt = *rec.FirstSeenAt
	default:
		return MLSLeafNewest{}, false, errors.New("mls leaf newest record is malformed")
	}
	return out, true, nil
}

// SaveMLSLeafNewest always writes version 2, so FirstSeenAt is required.
func SaveMLSLeafNewest(store SecretStore, ownerAccountID, peerAccountID string, rec MLSLeafNewest) error {
	rec.V = MLSLeafNewestVersion
	if rec.NotBefore <= 0 || rec.Fingerprint == "" || rec.FirstSeenAt <= 0 {
		return errors.New("mls leaf newest record is malformed")
	}
	encoded, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	return store.Set(config.Service, MLSLeafNewestAccount(ownerAccountID, peerAccountID), string(encoded))
}
