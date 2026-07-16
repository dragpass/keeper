// actions_archive_quorum.go — Wire-protocol Action* constants for the
// archive-key admin quorum (Shamir N-of-M break-glass) flow.
//
// Split out of actions.go for domain locality. Pure move — see actions.go for
// the wire-protocol contract note. Constant names / string values are
// unchanged.

package proto

const (
	// Archive-key admin quorum (Shamir N-of-M break-glass).
	//
	// ArchiveKeySplit: Shamir-split the org archive private key into
	//   len(recipient_public_keys) shares with threshold_n reconstruction,
	//   hybrid-wrap each share to an admin's account archive public key, then
	//   DELETE the archive private key. Not idempotent — a missing private key
	//   slot → not_found. After this the whole private key exists nowhere at
	//   rest; only the shares do.
	// ArchiveShareRewrap: an approving admin re-wraps their own share from
	//   their account archive key to the recovery session public key. Uses the
	//   admin's account archive private slot; shares are hybrid envelopes, not
	//   32B DEKs, so this is distinct from archive_unwrap_and_rewrap.
	// ArchiveSessionBegin / ArchiveSessionEnd: create / destroy the
	//   coordinator's ephemeral recovery-session keypair (its own slot).
	// ArchiveQuorumCombineAndRewrap: coordinator unwraps N re-wrapped shares
	//   with the session private key, reconstructs the archive private key,
	//   unwraps the OLD Group DEK, and re-wraps it to the target members. All
	//   reconstructed key material is wiped before returning; only the new
	//   per-recipient wraps are in the response.
	ActionArchiveKeySplit               = "archive_key_split"
	ActionArchiveShareRewrap            = "archive_share_rewrap"
	ActionArchiveSessionBegin           = "archive_session_begin"
	ActionArchiveSessionEnd             = "archive_session_end"
	ActionArchiveQuorumCombineAndRewrap = "archive_quorum_combine_and_rewrap"
)
