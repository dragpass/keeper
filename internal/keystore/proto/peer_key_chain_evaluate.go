// peer_key_chain_evaluate.go — the wrap-free trust evaluation payloads
// (account key trust v1).
//
// Same inputs as a wrap minus the ciphertext: an owner, a peer, the public key
// the server is serving right now, and the chain that claims to explain it.
// The response is the state machine's verdict and nothing else — no key
// material, no wrap output, only a fingerprint (a hash of public material), a
// state word, and a boolean.
//
// Contract: dragpass-control-plane
// docs/exec-plans/active/account-key-trust-implementation.md §6.2, §6.4.

package proto

// PeerKeyChainEvaluateRequest asks the Keeper to judge a peer's current key
// against the pin, without wrapping anything to it.
//
// `public_key` is the PEM exactly as the server served it. The Keeper hashes
// those bytes itself rather than taking a fingerprint from the caller, for the
// same reason peer_key_pin_verify does: a fingerprint the caller supplies is a
// fingerprint the caller chose.
type PeerKeyChainEvaluateRequest struct {
	OwnerAccountID     string                 `json:"owner_account_id"`
	AccountID          string                 `json:"account_id"`
	PublicKey          string                 `json:"public_key"`
	RotationStatements []KeyRotationStatement `json:"rotation_statements,omitempty"`
}

func (r PeerKeyChainEvaluateRequest) Validate() error {
	if err := requireMessageUUID(r.OwnerAccountID, "owner_account_id"); err != nil {
		return err
	}
	if err := requireMessageUUID(r.AccountID, "account_id"); err != nil {
		return err
	}
	if err := requirePEM(r.PublicKey, "public_key"); err != nil {
		return err
	}
	return ValidateKeyRotationStatements(r.RotationStatements)
}

// PeerKeyChainEvaluateResponseData is the verdict.
//
// It is returned on the success envelope even when `state` is `changed`,
// because the action succeeded at what it was asked to do: report what the
// Keeper thinks of this key. `changed` is a verdict, not a failed evaluation,
// and the caller of this action is precisely the code that wants to tell the
// four states apart. The wrap actions keep the refusal envelope, since there
// the verdict decides whether output exists at all.
type PeerKeyChainEvaluateResponseData struct {
	// State is `tofu`, `verified`, `rotated`, or `changed`.
	State string `json:"state"`
	// Fingerprint is what the Keeper computed from the supplied PEM, never a
	// value the caller sent.
	Fingerprint string `json:"fingerprint"`
	// Advanced reports whether the stored pin moved: a pin created where
	// there was none, or an existing one carried to a new fingerprint by a
	// valid chain. False when the key was already the pinned one (only
	// last_seen_at moved) and false on every refusal.
	Advanced bool `json:"advanced"`
	// PinnedFingerprint rides along on `changed` only, so the caller can put
	// the two side by side the way the peer_key_changed refusal does. Empty
	// otherwise.
	PinnedFingerprint string `json:"pinned_fingerprint,omitempty"`
}
