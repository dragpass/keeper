// peer_key_pin.go — the four pin management payloads (account key trust v1).
//
// None of these types carries key material in either direction. What crosses
// the bridge is a fingerprint (a hash of a public key), a state word, and three
// timestamps. `peer_key_pin_verify` is the one exception in shape only: it
// takes the public key PEM the server is currently serving so the Keeper can
// recompute the fingerprint itself rather than take the caller's word for it,
// and a public key is public material.
//
// Contract: dragpass-control-plane
// docs/exec-plans/active/account-key-trust-implementation.md §6.4.

package proto

// PeerKeyPinInfo is one pin as the Extension sees it. Deliberately not the
// stored record: `last_rotation_fingerprint` stays inside the Keeper, because
// the SPA has no use for the previous key's fingerprint and showing it would
// invite comparing the wrong pair.
type PeerKeyPinInfo struct {
	AccountID   string `json:"account_id"`
	Fingerprint string `json:"fingerprint"`
	State       string `json:"state"`
	FirstSeenAt int64  `json:"first_seen_at"`
	LastSeenAt  int64  `json:"last_seen_at"`
	VerifiedAt  int64  `json:"verified_at,omitempty"`
}

// PeerKeyPinListRequest asks for every pin this owner holds on this device.
type PeerKeyPinListRequest struct {
	OwnerAccountID string `json:"owner_account_id"`
}

func (r PeerKeyPinListRequest) Validate() error {
	return requireMessageUUID(r.OwnerAccountID, "owner_account_id")
}

// PeerKeyPinListResponseData carries the pins in index order. An owner with no
// pins gets an empty list, not an error.
type PeerKeyPinListResponseData struct {
	Pins []PeerKeyPinInfo `json:"pins"`
}

// PeerKeyPinGetRequest reads one pin.
type PeerKeyPinGetRequest struct {
	OwnerAccountID string `json:"owner_account_id"`
	AccountID      string `json:"account_id"`
}

func (r PeerKeyPinGetRequest) Validate() error {
	if err := requireMessageUUID(r.OwnerAccountID, "owner_account_id"); err != nil {
		return err
	}
	return requireMessageUUID(r.AccountID, "account_id")
}

// PeerKeyPinGetResponseData reports absence as data rather than as not_found:
// "this peer has never been observed" is the ordinary first-run answer, and the
// caller branches on it to decide whether to fetch a rotation chain at all.
type PeerKeyPinGetResponseData struct {
	Found bool            `json:"found"`
	Pin   *PeerKeyPinInfo `json:"pin,omitempty"`
}

// PeerKeyPinVerifyRequest confirms a fingerprint a human compared out of band.
//
// Both the fingerprint and the key are required, and the Keeper checks that
// they agree. That check is the point of the action: if the user read out
// fingerprint A over the phone while the server is now serving key B, promoting
// B to `verified` would launder exactly the substitution the pin exists to
// catch.
type PeerKeyPinVerifyRequest struct {
	OwnerAccountID string `json:"owner_account_id"`
	AccountID      string `json:"account_id"`
	Fingerprint    string `json:"fingerprint"`
	PublicKey      string `json:"public_key"`
}

func (r PeerKeyPinVerifyRequest) Validate() error {
	if err := requireMessageUUID(r.OwnerAccountID, "owner_account_id"); err != nil {
		return err
	}
	if err := requireMessageUUID(r.AccountID, "account_id"); err != nil {
		return err
	}
	if err := requireKeyFingerprint(r.Fingerprint, "fingerprint"); err != nil {
		return err
	}
	return requirePEM(r.PublicKey, "public_key")
}

// PeerKeyPinVerifyResponseData echoes the settled state. `state` is always
// `verified` — the action has one outcome, and anything else is an error.
type PeerKeyPinVerifyResponseData struct {
	State       string `json:"state"`
	Fingerprint string `json:"fingerprint"`
}

// PeerKeyPinForgetRequest discards a pin deliberately. This is the only way a
// pin goes away: account reset and logout leave pins alone, so a human's
// verification survives signing back in on the same device.
type PeerKeyPinForgetRequest struct {
	OwnerAccountID string `json:"owner_account_id"`
	AccountID      string `json:"account_id"`
}

func (r PeerKeyPinForgetRequest) Validate() error {
	if err := requireMessageUUID(r.OwnerAccountID, "owner_account_id"); err != nil {
		return err
	}
	return requireMessageUUID(r.AccountID, "account_id")
}

// PeerKeyPinForgetResponseData reports whether a pin was actually there.
// Idempotent: forgetting nothing succeeds with `forgotten:false`.
type PeerKeyPinForgetResponseData struct {
	Forgotten bool `json:"forgotten"`
}
