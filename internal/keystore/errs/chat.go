package errs

// Conversation-state and MLS codes. Unlike the coarse codes in errs.go they
// are uppercase and name the exact refusal.
const (
	// ErrCodeChatStateInvalidInput — malformed syntax, wrong size, unknown or
	// duplicate or missing field, or an out-of-range count.
	ErrCodeChatStateInvalidInput ErrorCode = "CHAT_STATE_INVALID_INPUT"

	// ErrCodeChatStateNotAuthorized — permit signature, binding, or window
	// failure. One code for all three: which check refused is not something an
	// unauthorized caller gets to learn.
	ErrCodeChatStateNotAuthorized ErrorCode = "CHAT_STATE_NOT_AUTHORIZED"

	// ErrCodeChatStateLockTimeout — another process held the conversation
	// longer than the ceiling. Its own code so the caller never has to infer
	// from a generic failure whether proceeding without the lock is an option.
	// It is not.
	ErrCodeChatStateLockTimeout ErrorCode = "CHAT_STATE_LOCK_TIMEOUT"

	// ErrCodeChatStateConflict — the state changed between the read and the
	// write inside one locked section, or the named position is already taken
	// by another message. Both mean the write did not happen.
	ErrCodeChatStateConflict ErrorCode = "CHAT_STATE_CONFLICT"

	// ErrCodeChatStateRekeyRequired — the stored state is behind the anchor
	// or behind the server's watermark. Sending is locked for this conversation
	// until a new epoch is established. There is no "retry anyway": continuing
	// on a rewound chain is the failure this whole path exists to prevent.
	ErrCodeChatStateRekeyRequired ErrorCode = "CHAT_STATE_REKEY_REQUIRED"

	// ErrCodeChatStateNotFound — no outbox entry for that client message id.
	// A retransmission this late is abandoned rather than re-encrypted.
	ErrCodeChatStateNotFound ErrorCode = "CHAT_STATE_NOT_FOUND"

	// ErrCodeChatStateStorageFailure — the state directory or the keyring
	// could not be read or written. Nothing was committed.
	ErrCodeChatStateStorageFailure ErrorCode = "CHAT_STATE_STORAGE_FAILURE"

	// ErrCodeChatMLSLeafUntrusted — a leaf that would enter the group is
	// not vouched for by its account: no declaration, a malformed one, a bad
	// signature, a declaration for another account, device or key, a
	// superseded declaration, or an account whose key the pin reports as
	// changed (design §5.3, §13). Nothing was applied and nothing was
	// recorded. There is no "ignore and continue".
	ErrCodeChatMLSLeafUntrusted             ErrorCode = "CHAT_MLS_LEAF_UNTRUSTED"
	ErrCodeChatMLSKeyTransparencyUnverified ErrorCode = "CHAT_MLS_KEY_TRANSPARENCY_UNVERIFIED"
	ErrCodeChatMLSKeyTransparencyFork       ErrorCode = "CHAT_MLS_KEY_TRANSPARENCY_FORK"
	// ErrCodeChatMLSKeyTransparencyTrustInvalid — a trust file is
	// configured but could not be read or parsed. Every entering leaf is
	// refused until it is fixed; there is no fallback to TOFU.
	ErrCodeChatMLSKeyTransparencyTrustInvalid ErrorCode = "CHAT_MLS_KEY_TRANSPARENCY_TRUST_INVALID"

	// ErrCodeChatMLSCapabilityRequired — this Keeper binary was built
	// without the MLS library (design §13).
	ErrCodeChatMLSCapabilityRequired ErrorCode = "CHAT_MLS_CAPABILITY_REQUIRED"

	// ErrCodeChatMLSRotationPending — a permit has named an account this
	// device's confirmed group still holds a leaf for as removed from the
	// organization, and this device has not yet applied a Commit that takes
	// that leaf out (design §6.4.1 S-1). New application messages in the
	// conversation are refused; receiving and Commits are not. The same code
	// the server answers POST /:id/messages with, because the server refusing
	// alone means nothing under a server that is not honest.
	ErrCodeChatMLSRotationPending ErrorCode = "CHAT_MLS_ROTATION_PENDING"

	// ErrCodeChatMLSLeafReplacementPending — a permit has named an account
	// as taken over by a new device (design M4.4), and this device's confirmed
	// group still holds a leaf of that account under another key. The old
	// device may be lost or stolen and its leaf holds the current epoch keys,
	// so new application messages are refused until a replace Commit that
	// takes that leaf out is confirmed here. Receiving and Commits are not
	// refused.
	ErrCodeChatMLSLeafReplacementPending ErrorCode = "CHAT_MLS_LEAF_REPLACEMENT_PENDING"

	// ErrCodeChatMLSCommitPending — this device has a Commit whose CAS
	// outcome it has not been told (design §7.3.2). A new Commit, a new send
	// and a new MLS open are refused until mls_commit_confirm settles it;
	// a retransmission and a history re-read are not.
	ErrCodeChatMLSCommitPending ErrorCode = "CHAT_MLS_COMMIT_PENDING"

	// ErrCodeChatMLSEpochStale — the request does not continue this device's
	// confirmed epoch: a send or Commit built for another epoch than the one
	// the group is on, or a handshake that is already applied or comes after
	// one that is not. The server answers its own CAS failure with the same
	// code; this is the Keeper-side meaning.
	ErrCodeChatMLSEpochStale ErrorCode = "CHAT_MLS_EPOCH_STALE"

	// ErrCodeChatMLSFailed — the MLS operation itself failed or refused: a
	// message that does not open, a declaration that does not match the
	// position, a Welcome for another conversation, a group state that does
	// not exist yet. Nothing was written.
	ErrCodeChatMLSFailed ErrorCode = "CHAT_MLS_FAILED"

	// ErrCodeChatMLSWelcomeUnusable — this device holds no private keys for
	// any KeyPackage the Welcome is addressed to: the KeyPackage expired, was
	// already used, or belonged to a leaf a promote has since replaced. The
	// invitation cannot be used on this device, and retrying cannot change
	// that; the member has to be invited again with a KeyPackage of the
	// current leaf. Nothing was written and the pool is unchanged.
	ErrCodeChatMLSWelcomeUnusable ErrorCode = "CHAT_MLS_WELCOME_UNUSABLE"

	// ErrCodeChatMLSCommitUnauthorized — a Commit this device was asked to
	// build carries an Add or a Remove the authority rules do not allow
	// (0.0.55). Nothing was built. A received Commit the rules refuse is not
	// this code: it is CHAT_MLS_ROW_REFUSED.
	ErrCodeChatMLSCommitUnauthorized ErrorCode = "CHAT_MLS_COMMIT_UNAUTHORIZED"

	// ErrCodeChatMLSRoomRecreateRequired — this device was asked to build a
	// Commit on a group whose context carries no roles (0.0.58). No Keeper
	// accepts one, so the conversation takes no Commit any more and the room
	// must be recreated. Nothing was built.
	ErrCodeChatMLSRoomRecreateRequired ErrorCode = "CHAT_MLS_ROOM_RECREATE_REQUIRED"

	// ErrCodeChatMLSRowRefused — mls_process (or a superseded
	// mls_commit_confirm) refused a received Commit the authority rules do
	// not allow (N3). Nothing was applied. The conversation is not latched:
	// it stops at that epoch (sync_blocked in the status, MLSSyncBlock in
	// data), a new message is refused with CHAT_MLS_SYNC_BLOCKED, and another
	// valid Commit for the same epoch is applied as usual and clears it. A
	// received Commit refused by the leaf check keeps its own code
	// (CHAT_MLS_LEAF_UNTRUSTED) and blocks the same way.
	ErrCodeChatMLSRowRefused ErrorCode = "CHAT_MLS_ROW_REFUSED"

	// ErrCodeChatMLSSyncBlocked — a new message was refused because the
	// conversation is stopped at a received Commit this device refused
	// (sync_blocked). Nothing was consumed.
	ErrCodeChatMLSSyncBlocked ErrorCode = "CHAT_MLS_SYNC_BLOCKED"

	// ErrCodeChatMLSRejoinUnverified — a rejoin in mls_commit_build carries
	// a request that is not the account's own signed statement for this
	// conversation and this KeyPackage's leaf, or one too old (0.0.55).
	// Nothing was built.
	ErrCodeChatMLSRejoinUnverified ErrorCode = "CHAT_MLS_REJOIN_UNVERIFIED"

	// ErrCodeChatMLSPeerUnverified — this device's strict policy
	// (require_verified_peers) is on and the operation would bring in, or
	// send to, another account whose key no person here verified: a local
	// Add or Join of such a leaf, or a send in a conversation that holds one
	// (0.0.55, design Q8). Carries MLSPeerUnverifiedData naming them. Nothing
	// was built, joined, consumed or written. A received Commit is never
	// refused for this.
	ErrCodeChatMLSPeerUnverified ErrorCode = "CHAT_MLS_PEER_UNVERIFIED"

	// ErrCodeChatMLSStatementUnverified — a signed statement handed to
	// mls_commit_build does not verify. Nothing was built.
	ErrCodeChatMLSStatementUnverified ErrorCode = "CHAT_MLS_STATEMENT_UNVERIFIED"

	// ErrCodeChatMLSRolesUnsupported — a member's leaf or KeyPackage does not
	// advertise the room roles extension, which a group carrying roles
	// requires of every leaf. That member's Keeper must update. Nothing was
	// built.
	ErrCodeChatMLSRolesUnsupported ErrorCode = "CHAT_MLS_ROLES_UNSUPPORTED"

	// ErrCodeChatMLSHandoverInvalid — a leaf handover does not verify, names
	// another succession than the one it is offered for, or, at signing, is asked
	// for a declaration this device's account key did not sign, for this device
	// itself, or for a request whose window has closed. Nothing was signed or
	// built.
	ErrCodeChatMLSHandoverInvalid ErrorCode = "CHAT_MLS_HANDOVER_INVALID"
)
