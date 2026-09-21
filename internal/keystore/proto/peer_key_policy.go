// peer_key_policy.go — the two strict-mode payloads (account key trust v1).
//
// One boolean in each direction. No key material, no fingerprints, no account
// ids: the policy is about this device and says nothing about who is signed in
// or whom they talk to.
//
// Contract: dragpass-control-plane
// docs/exec-plans/active/account-key-trust-implementation.md §6.5.

package proto

// PeerKeyPolicyGetRequest takes nothing. Declared anyway so the action goes
// through the same decode / validate path as every other one.
type PeerKeyPolicyGetRequest struct{}

func (r PeerKeyPolicyGetRequest) Validate() error { return nil }

// PeerKeyPolicySetRequest turns strict mode on or off.
//
// The field is a pointer so a payload that omits it is a validation error
// rather than a silent `false`. Defaulting would let a malformed call switch
// the protection off, which is the one direction this action must not move by
// accident.
type PeerKeyPolicySetRequest struct {
	RequireVerifiedPeers *bool `json:"require_verified_peers"`
}

func (r PeerKeyPolicySetRequest) Validate() error {
	if r.RequireVerifiedPeers == nil {
		return newValidationError("require_verified_peers", "must be present")
	}
	return nil
}

// PeerKeyPolicyResponseData is what both actions return, so a set reports the
// value that is now stored rather than echoing what was asked for.
type PeerKeyPolicyResponseData struct {
	RequireVerifiedPeers bool `json:"require_verified_peers"`
}
