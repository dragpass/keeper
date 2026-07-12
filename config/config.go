package config

const (
	Service                         = "com.dragpass.keeper"
	DeviceKey                       = "device_key"
	DragPassKeeperPrivateKey        = "keeper_private_key"
	DragPassKeeperPublicKey         = "keeper_public_key"
	DragPassServerPublicKey         = "server_public_key"
	SessionCode                     = "session_code"
	PendingDragPassKeeperPrivateKey = "pending_keeper_private_key"
	PendingDragPassKeeperPublicKey  = "pending_keeper_public_key"

	// Multi-version server public key infrastructure.
	//
	// DragPassServerPublicKeyVersionedPrefix + version number stores v1/v2/...
	// entries.
	// DragPassServerPublicKeyActiveVersion is a pointer to the active version
	// (string, e.g. "1").
	// DragPassServerRootPublicKeyFingerprint is the Root public key
	// fingerprint TOFU pin.
	//
	// The existing single slot DragPassServerPublicKey is kept as a mirror of
	// the active key PEM (legacy compat). Once the Extension always specifies
	// server_key_version on challenge requests, this mirror can be deprecated.
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
