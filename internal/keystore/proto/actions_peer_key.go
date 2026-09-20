// actions_peer_key.go — Wire-protocol Action* constants for peer account key
// pin management (account key trust v1).
//
// Its own actions_* / registry_* fragment pair rather than a corner of the
// Group DEK catalog, for the same reason the chat and message actions have
// theirs: this is a distinct security domain. Nothing here decrypts anything.
// These four actions read and write the trust record that the two wrap actions
// consult, and the record is the only thing on this device a malicious server
// cannot reach.
//
// Contract: dragpass-control-plane
// docs/exec-plans/active/account-key-trust-implementation.md §6.4.

package proto

const (
	// PeerKeyPinList: every pin this owner holds on this device.
	//
	//   Inputs: owner_account_id
	//   Output: { pins: [{ account_id, fingerprint, state, first_seen_at,
	//             last_seen_at, verified_at? }] }
	//
	// Pins are owner-scoped, so the id in the request selects the set. It is
	// not an authorization check and is not treated as one: a caller naming
	// someone else's id gets that owner's pins only if they are already on
	// this device under this OS user, and what leaks is a list of
	// fingerprints. The scoping exists so two accounts sharing a machine do
	// not overwrite each other's trust decisions.
	ActionPeerKeyPinList = "peer_key_pin_list"

	// PeerKeyPinGet: one pin, or the fact that there is none.
	//
	//   Inputs: owner_account_id, account_id
	//   Output: { found, pin? }
	//
	// Absence is data rather than not_found. The caller uses it to decide
	// whether to fetch a rotation chain before the next wrap: with no pin the
	// first observation is trust-on-first-use and a chain would prove nothing.
	ActionPeerKeyPinGet = "peer_key_pin_get"

	// PeerKeyPinVerify: settle a fingerprint a human compared out of band.
	//
	//   Inputs: owner_account_id, account_id, fingerprint (hex 64),
	//           public_key (PEM the server is serving right now)
	//   Output: { state: "verified", fingerprint }
	//
	// The Keeper recomputes the fingerprint from the PEM and refuses with
	// crypto_failure if it differs from the one in the request, leaving the
	// pin untouched. Without that check the action would promote whatever key
	// the server happens to be serving at the moment a user confirms a
	// different one they read aloud — which is the substitution the whole
	// model exists to catch. Verification also works on a peer with no pin
	// yet: the user checked before anything was observed.
	ActionPeerKeyPinVerify = "peer_key_pin_verify"

	// PeerKeyPinForget: discard a pin deliberately.
	//
	//   Inputs: owner_account_id, account_id
	//   Output: { forgotten }
	//
	// The only path that removes a pin. Account reset and logout leave them
	// alone on purpose, so signing back in on the same device keeps whatever
	// a human already confirmed. Idempotent — forgetting nothing succeeds
	// with forgotten:false and still prunes a stale index entry.
	ActionPeerKeyPinForget = "peer_key_pin_forget"
)
