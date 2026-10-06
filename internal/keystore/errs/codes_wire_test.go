package errs

import "testing"

// The values are wire contract: the App, the Extension and ariadne match on
// them. Renaming a constant is free; changing a value here is a protocol
// change and needs a docs/protocol.md entry.
func TestErrorCodeWireValues(t *testing.T) {
	pinned := []struct {
		code ErrorCode
		wire string
	}{
		{ErrCodeValidation, "validation_error"},
		{ErrCodeNotFound, "not_found"},
		{ErrCodeExpiredSession, "expired_session"},
		{ErrCodeCryptoFailure, "crypto_failure"},
		{ErrCodeStorageFailure, "storage_failure"},
		{ErrCodeUnsupported, "unsupported"},
		{ErrCodeInternal, "internal_error"},
		{ErrCodePasswordInvalid, "password_invalid"},
		{ErrCodeSignupPending, "signup_pending"},
		{ErrCodeAccountKeyStaged, "account_key_staged"},
		{ErrCodePeerKeyChanged, "peer_key_changed"},
		{ErrCodePeerKeyUnverified, "peer_key_unverified"},
		{ErrCodePeerKeyOwnerMismatch, "peer_key_owner_mismatch"},
		{ErrCodeChatRuntimeBusy, "chat_runtime_busy"},
		{ErrCodeChatRuntimeLeaseRequired, "chat_runtime_lease_required"},
		{ErrCodeChatRuntimeRevoked, "chat_runtime_revoked"},
		{ErrCodeKeyTransparencyUnverified, "key_transparency_unverified"},
		{ErrCodeKeyTransparencyFork, "key_transparency_fork"},
		{ErrCodeKeyTransparencyTrustInvalid, "key_transparency_trust_invalid"},
		{ErrCodeChatStateInvalidInput, "CHAT_STATE_INVALID_INPUT"},
		{ErrCodeChatStateNotAuthorized, "CHAT_STATE_NOT_AUTHORIZED"},
		{ErrCodeChatStateLockTimeout, "CHAT_STATE_LOCK_TIMEOUT"},
		{ErrCodeChatStateConflict, "CHAT_STATE_CONFLICT"},
		{ErrCodeChatStateRekeyRequired, "CHAT_STATE_REKEY_REQUIRED"},
		{ErrCodeChatStateNotFound, "CHAT_STATE_NOT_FOUND"},
		{ErrCodeChatStateStorageFailure, "CHAT_STATE_STORAGE_FAILURE"},
		{ErrCodeChatMLSLeafUntrusted, "CHAT_MLS_LEAF_UNTRUSTED"},
		{ErrCodeChatMLSKeyTransparencyUnverified, "CHAT_MLS_KEY_TRANSPARENCY_UNVERIFIED"},
		{ErrCodeChatMLSKeyTransparencyFork, "CHAT_MLS_KEY_TRANSPARENCY_FORK"},
		{ErrCodeChatMLSKeyTransparencyTrustInvalid, "CHAT_MLS_KEY_TRANSPARENCY_TRUST_INVALID"},
		{ErrCodeChatMLSCapabilityRequired, "CHAT_MLS_CAPABILITY_REQUIRED"},
		{ErrCodeChatMLSRotationPending, "CHAT_MLS_ROTATION_PENDING"},
		{ErrCodeChatMLSLeafReplacementPending, "CHAT_MLS_LEAF_REPLACEMENT_PENDING"},
		{ErrCodeChatMLSCommitPending, "CHAT_MLS_COMMIT_PENDING"},
		{ErrCodeChatMLSEpochStale, "CHAT_MLS_EPOCH_STALE"},
		{ErrCodeChatMLSFailed, "CHAT_MLS_FAILED"},
		{ErrCodeChatMLSWelcomeUnusable, "CHAT_MLS_WELCOME_UNUSABLE"},
		{ErrCodeChatMLSCommitUnauthorized, "CHAT_MLS_COMMIT_UNAUTHORIZED"},
		{ErrCodeChatMLSRoomRecreateRequired, "CHAT_MLS_ROOM_RECREATE_REQUIRED"},
		{ErrCodeChatMLSRowRefused, "CHAT_MLS_ROW_REFUSED"},
		{ErrCodeChatMLSSyncBlocked, "CHAT_MLS_SYNC_BLOCKED"},
		{ErrCodeChatMLSRejoinUnverified, "CHAT_MLS_REJOIN_UNVERIFIED"},
		{ErrCodeChatMLSPeerUnverified, "CHAT_MLS_PEER_UNVERIFIED"},
		{ErrCodeChatMLSStatementUnverified, "CHAT_MLS_STATEMENT_UNVERIFIED"},
		{ErrCodeChatMLSRolesUnsupported, "CHAT_MLS_ROLES_UNSUPPORTED"},
		{ErrCodeChatMLSHandoverInvalid, "CHAT_MLS_HANDOVER_INVALID"},
	}
	seen := map[ErrorCode]bool{}
	for _, p := range pinned {
		if string(p.code) != p.wire {
			t.Errorf("error code %q changed its wire value from %q", p.code, p.wire)
		}
		if seen[p.code] {
			t.Errorf("error code %q is defined twice", p.code)
		}
		seen[p.code] = true
	}
}
