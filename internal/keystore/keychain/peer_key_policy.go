package keychain

// peer_key_policy.go — the device-local peer key policy (account key trust v1,
// strict mode).
//
// One entry under config.Service, no owner in the name:
//
//	peer-key-policy → {"v":1,"require_verified_peers":true}
//
// Pins answer "is this the key I accepted for this peer"; the policy answers
// "how much do I insist on before I wrap at all". The first is per owner
// account, the second is per machine, which is why this slot is not scoped the
// way peer-pin: is. A machine that requires out-of-band checks requires them
// for whoever is signed in.
//
// The server can neither read nor write it. It lives in the keyring next to
// the pins, reached through the same SecretStore interface, and the only
// callers are the two policy actions and the wrap enforcement path.
//
// Contract: dragpass-control-plane
// docs/exec-plans/active/account-key-trust-implementation.md §6.5.

import (
	"encoding/json"
	"errors"

	"github.com/dragpass/keeper/config"
)

// PeerKeyPolicyVersion is the schema version written into the record. A reader
// that meets a higher number is looking at a format it does not know.
const PeerKeyPolicyVersion = 1

// PeerKeyPolicy is the stored record.
//
// RequireVerifiedPeers off is the default and the shipped behaviour: a wrap to
// a `tofu` or `rotated` peer goes through and only an unexplained key change
// is refused. On, the wrap path also refuses anything a human has not compared
// out of band.
type PeerKeyPolicy struct {
	V                    int  `json:"v"`
	RequireVerifiedPeers bool `json:"require_verified_peers"`
}

// GetPeerKeyPolicy reads the policy. A device that has never set one gets the
// default (everything off) rather than an error: absence is the shipped state,
// not a failure, and the wrap path reads this on every enforced call.
func GetPeerKeyPolicy(store SecretStore) (PeerKeyPolicy, error) {
	raw, err := store.Get(config.Service, config.PeerKeyPolicyAccount)
	if err != nil {
		if errors.Is(err, ErrSecretNotFound) {
			return PeerKeyPolicy{V: PeerKeyPolicyVersion}, nil
		}
		return PeerKeyPolicy{}, err
	}
	var policy PeerKeyPolicy
	if err := json.Unmarshal([]byte(raw), &policy); err != nil {
		// Deliberately an error rather than a silent fall back to the
		// default. Falling back would turn an unreadable record into a quiet
		// relaxation of the very setting the user turned on.
		return PeerKeyPolicy{}, errors.New("peer key policy record is not readable JSON")
	}
	return policy, nil
}

// SavePeerKeyPolicy writes the policy, stamping the current schema version.
func SavePeerKeyPolicy(store SecretStore, policy PeerKeyPolicy) error {
	policy.V = PeerKeyPolicyVersion
	encoded, err := json.Marshal(policy)
	if err != nil {
		return err
	}
	return store.Set(config.Service, config.PeerKeyPolicyAccount, string(encoded))
}
