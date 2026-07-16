// actions_archive.go — Wire-protocol Action* constants for per-org and
// per-account Archive / Recovery keypairs and the break-glass re-grant
// composite. Archive quorum (Shamir N-of-M) actions live in
// actions_archive_quorum.go.
//
// Split out of actions.go for domain locality. Pure move — see actions.go for
// the wire-protocol contract note. Constant names / string values are
// unchanged.

package proto

const (
	// per-org Archive / Recovery keypair actions.
	//
	// ArchiveKeyGenerate: generate an RSA archive keypair. If an active key
	//                     already exists, this is a no-op returning only its
	//                     meta (idempotent). The private key is stored in a
	//                     dedicated slot and never leaves it.
	// ArchiveKeyStatus:   whether an active archive key exists + public key +
	//                     fingerprint. Absence is normal (archive not enabled).
	//
	// The archive key is a break-glass recovery key: during group DEK rotation
	// the OLD Group DEK is additionally wrapped to its public half so the org
	// owner can recover past DEKs. It is never used for identity / login /
	// recovery / request signing.
	ActionArchiveKeyGenerate = "archive_key_generate"
	ActionArchiveKeyStatus   = "archive_key_status"

	// Per-account Archive / Recovery receiving keypair actions.
	//
	// AccountArchiveKeyGenerate / AccountArchiveKeyStatus: same idempotent
	// generate / status contract as the org archive actions, but against the
	// dedicated ACCOUNT slot (account_archive_private_key). This is the key
	// whose public half the account publishes to the server directory
	// (account_archive_keys) to receive ownership-handoff grants and archive
	// quorum Shamir shares. Kept as separate actions (rather than a slot
	// parameter on archive_key_*) because the two keys have different
	// lifecycles: the org key is deleted by archive_key_split when quorum is
	// enabled, while the account key must survive that wipe.
	ActionAccountArchiveKeyGenerate = "account_archive_key_generate"
	ActionAccountArchiveKeyStatus   = "account_archive_key_status"

	// ArchiveUnwrapAndRewrap: break-glass re-grant composite. Unwrap an OLD
	// Group DEK that was wrapped to the org archive public key
	// (org_owner_archive grant) with the archive private key, then re-wrap it
	// to a target member's public key. The raw Group DEK lives only briefly in
	// Keeper memory (memguard) and is never in the response — same raw-free
	// pattern as dek_rewrap_for_member. The archive private key never leaves
	// its slot. Unwrap tries the org slot first and falls back to the account
	// archive slot on decrypt failure — after an ownership handoff the grants
	// are wrapped to the new owner's account directory key, not their org
	// slot key. Both slots missing → not_found.
	ActionArchiveUnwrapAndRewrap = "archive_unwrap_and_rewrap"
)
