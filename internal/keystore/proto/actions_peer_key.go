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

	// PeerKeySafetyNumber: the pairwise safety number of this owner and one
	// peer (0.0.55, design Q10 (a)).
	//
	//   Inputs: owner_account_id, account_id, public_key (the peer's PEM as
	//           the directory serves it)
	//   Output: { safety_number (60 digits), safety_number_b64 (32 bytes),
	//             own_fingerprint, peer_fingerprint }
	//
	// SHA-256 over dragpass.safety_number|1| and the two (account_id,
	// account key fingerprint) pairs sorted by account id, so both sides of
	// the pair compute the same value. The own half comes from this Keeper's
	// own key, never from the request. Carries nothing secret.
	ActionPeerKeySafetyNumber = "peer_key_safety_number"

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

	// PeerKeyChainEvaluate: judge a peer's current key without wrapping to it.
	//
	//   Inputs: owner_account_id, account_id, public_key (PEM the server is
	//           serving right now), rotation_statements?
	//   Output: { state, fingerprint, advanced, pinned_fingerprint? }
	//
	// The pin only advanced to `rotated` inside a wrap, and the SPA blocks
	// every wrap entry point while the pinned fingerprint differs from the
	// served key. A peer who rotated legitimately therefore locked the org:
	// the chain that explains the change existed, and nothing could ever show
	// it to the Keeper. The two escapes the banner offered were both wrong —
	// out-of-band verify lands on `verified` and erases the "this key
	// changed" signal (and the same button launders a real substitution),
	// while forget throws the protection away.
	//
	// This action gives the chain somewhere to be judged. It runs the same
	// evaluatePeerKeyTrust the wrap path runs, on the same inputs, and
	// persists the pin the same way, so a valid chain moves the pin to
	// `rotated` and a refusal reports `changed` and changes nothing.
	//
	// It does not widen what a local caller can do: anyone who can reach the
	// Keeper can already call the wrap actions, which take these same inputs
	// and run this same state machine before producing anything. What is
	// removed is the requirement to have a Group DEK in hand to ask the
	// question.
	ActionPeerKeyChainEvaluate = "peer_key_chain_evaluate"

	// PeerKeyOwnerReset: forget which account this device's pins belong to.
	//
	//   Inputs: none
	//   Output: { reset }
	//
	// The owner half of `peer-pin:<owner>:<peer>` arrives as a request field
	// sourced from the server, so the Keeper records the first owner id it
	// is ever given and refuses the rest with `peer_key_owner_mismatch`. This
	// is the only path that changes that record, and it exists because a
	// device legitimately shared by two accounts would otherwise be stuck on
	// whoever signed in first.
	//
	// **It must be reachable only from the extension options surface.** No
	// SPA route, no content script, no server-driven path may call it, since
	// a caller who can clear the record can then pick the namespace the
	// owner check exists to fix. The Keeper cannot enforce that itself: it
	// does not know who launched it (four surfaces spawn the same binary over
	// the same stdio loop — see docs/security/adr-ratchet-state-storage.md
	// §3.1), so this is a client-side obligation stated here rather than a
	// check.
	//
	// Pins are left behind, so switching back to a previous owner finds their
	// trust records where they were.
	ActionPeerKeyOwnerReset = "peer_key_owner_reset"

	// PeerKeyPolicyGet: the device's peer key policy.
	//
	//   Inputs: none
	//   Output: { require_verified_peers }
	//
	// A device that never set one reads the default, which is off. No owner
	// id: this is a setting about the machine, not about one account's view
	// of its peers.
	ActionPeerKeyPolicyGet = "peer_key_policy_get"

	// PeerKeyPolicySet: turn strict mode on or off.
	//
	//   Inputs: require_verified_peers
	//   Output: { require_verified_peers }
	//
	// On, the wrap path refuses any peer whose pin is not `verified` with
	// `peer_key_unverified`: a `tofu` peer nobody compared and a `rotated`
	// peer whose chain verified but whose current key nobody has read aloud.
	// `changed` is refused either way.
	//
	// The field is required rather than defaulted, so an empty payload turns
	// nothing off by accident. The extension options page is the only caller;
	// the SPA and the server have no route to it, which is the point of
	// keeping the value in the keyring instead of on the account.
	ActionPeerKeyPolicySet = "peer_key_policy_set"
)
