package config

const (
	Service                         = "com.dragpass.keeper"
	DeviceKey                       = "device_key"
	PersonalDeviceWrappedDEK        = "personal_device_wrapped_dek"
	PendingPersonalKeyBundle        = "pending_personal_key_bundle"
	DragPassKeeperPrivateKey        = "keeper_private_key"
	DragPassKeeperPublicKey         = "keeper_public_key"
	SessionCode                     = "session_code"
	PendingDragPassKeeperPrivateKey = "pending_keeper_private_key"
	PendingDragPassKeeperPublicKey  = "pending_keeper_public_key"

	// Server public keys are stored by version with an explicit active pointer.
	DragPassServerPublicKeyVersionedPrefix = "server_public_key_v"
	DragPassServerPublicKeyActiveVersion   = "server_public_key_active_version"
	DragPassServerRootPublicKeyFingerprint = "server_public_key_root_fingerprint"

	// Per-device request-signing key (Ed25519).
	//
	// Completely separate namespace from the account identity keypair
	// (DragPassKeeperPrivateKey). This key must never be used to perform
	// unwrap / login challenge / recovery. Even if key material is confused,
	// the RSA-OAEP / Ed25519 algorithm difference causes immediate failure,
	// but operational debugging becomes hard, so the slots themselves are
	// separated.
	DragPassRequestSigningPrivateKey = "request_signing_private_key"
	DragPassRequestSigningPublicKey  = "request_signing_public_key"

	// Pending slot for request-signing key rotation. `prepare` stores a new
	// key in the pending slot, `promote` overwrites the active slot. `abort`
	// only empties pending (active is untouched).
	PendingDragPassRequestSigningPrivateKey = "pending_request_signing_private_key"
	PendingDragPassRequestSigningPublicKey  = "pending_request_signing_public_key"

	// Per-org Archive / Recovery keypair (RSA-2048).
	//
	// A break-glass recovery key held on the org owner's device. Completely
	// separate namespace from the account identity keypair
	// (DragPassKeeperPrivateKey) — this key is only used to wrap OLD Group DEKs
	// during rotation (defense-in-depth org_owner_archive grant) and never for
	// identity / login / recovery / request signing. The private key never
	// leaves this slot.
	OrgArchivePrivateKey = "org_archive_private_key"
	OrgArchivePublicKey  = "org_archive_public_key"

	// Staging slot for same-device org archive key rotation.
	//
	// archive_key_generate is idempotent, so on the same device it can never
	// produce a genuinely new key. archive_key_rotate_begin instead generates a
	// new keypair into this staging slot while leaving the active slot
	// (OrgArchivePrivateKey) untouched — existing grants can still be re-wrapped
	// with the OLD active key (archive_unwrap_and_rewrap) until the rotation is
	// committed. archive_key_rotate_commit promotes staging → active and clears
	// staging; archive_key_rotate_abort just clears staging.
	OrgArchivePrivateKeyStaging = "org_archive_private_key_staging"
	OrgArchivePublicKeyStaging  = "org_archive_public_key_staging"

	// Per-account Archive / Recovery receiving keypair (RSA-2048).
	//
	// The key whose PUBLIC half this account publishes to the server-side
	// account directory (account_archive_keys) so it can RECEIVE material
	// wrapped to it: ownership-handoff re-wrapped grants and archive quorum
	// Shamir shares. A separate slot from the org archive keypair
	// (OrgArchivePrivateKey) — the org key is the org break-glass key that
	// archive_key_split deletes when quorum is enabled, while this account key
	// must survive that wipe (it is what the admin unwraps their quorum share
	// with). Never used for identity / login / request signing.
	AccountArchivePrivateKey = "account_archive_private_key"
	AccountArchivePublicKey  = "account_archive_public_key"

	// Peer account key pins (account key trust v1).
	//
	// One entry per (owner account, peer account) pair holds the pinned
	// fingerprint and its trust state; the index chunks make that set
	// enumerable, because SecretStore offers Get / Set / Delete and no
	// listing. Both names are assembled in keychain/peer_key_pin.go — the
	// prefixes live here so every slot the Keeper owns is visible in one
	// file. Not key material: a pin holds a hash of a public key.
	PeerKeyPinPrefix      = "peer-pin:"
	PeerKeyPinIndexPrefix = "peer-pin-index:"

	// Peer key device policy (account key trust v1, strict mode).
	//
	// A single entry, deliberately not owner-scoped: this is a decision about
	// the machine ("on this device, only wrap to keys somebody compared out
	// of band"), not about one account's view of its peers. Two accounts
	// sharing a device share the policy and keep separate pins.
	//
	// The server has no path to it. There is no action that lets a caller
	// read it on the server's behalf either — the two policy actions are
	// wired to the extension options page only.
	PeerKeyPolicyAccount = "peer-key-policy"

	// The owner account this device's pins belong to (account key trust v1,
	// owner TOFU).
	//
	// A single entry, like the policy and for the same structural reason: it
	// is a fact about the device, not about one account's view of its peers.
	// The owner half of `peer-pin:<owner>:<peer>` arrives in the request and
	// originally came from the server (`GET /account/me`), so a server that
	// reports a different account id would send every lookup into an empty
	// namespace where every peer looks new. This slot records the first owner
	// the Keeper ever saw and refuses the ones that disagree.
	//
	// Cleared only by peer_key_owner_reset, which is the single path that
	// lets a device change owners.
	PeerKeyOwnerAccount = "peer-key-owner"

	// Chat v2 conversation state (ADR S4).
	//
	// The keyring holds the two small things and none of the bulk. The seal
	// key is the 32-byte AES key every chat-state file of one owner is sealed
	// under, which is what makes the files alone worthless; the anchor is the
	// {generation, reserved_before, watermark} triple that decides whether a
	// state file has been rewound. The anchor has to live in a *different*
	// medium from the file it judges, otherwise restoring a backup restores
	// the judge along with the accused.
	//
	// Both names are assembled in chatstate/. The anchor's suffix is an HMAC
	// of (owner, conversation) under a key derived from the seal key, so the
	// keyring never carries a conversation id in a slot name.
	//
	// Deleting the seal key is what makes a purge final: an old state file
	// restored afterwards cannot be opened under the key that replaces it.
	ChatStateSealKeyPrefix = "chat-state-seal:"
	ChatStateAnchorPrefix  = "chat-state-anchor:"

	// Archive quorum recovery-session ephemeral keypair (RSA-2048).
	//
	// Created by archive_session_begin when the org owner (coordinator) opens a
	// break-glass recovery session, and deleted by archive_session_end. Quorum
	// admins re-wrap their Shamir shares to this session public key; the
	// coordinator's Keeper uses this private key to unwrap them in
	// archive_quorum_combine_and_rewrap. A short-lived slot scoped to a single
	// recovery session — never the archive key itself.
	OrgArchiveSessionPrivateKey = "org_archive_session_private_key"
	OrgArchiveSessionPublicKey  = "org_archive_session_public_key"
)
