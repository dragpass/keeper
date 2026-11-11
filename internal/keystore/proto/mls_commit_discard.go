package proto

import "slices"

// MLSCommitDiscardRefusedDefinitiveCodes are the server answers to a Commit
// post that refuse it for good and store nothing (ariadne
// `POST /conversations/:id/mls/commit`). Not every one of them proves that the
// server holds no Commit under that client_commit_id: ariadne checks
// conversation access (CHAT_ACCESS_DENIED) before its replay lookup, so a
// Commit accepted before the caller lost access is answered with it too.
// CHAT_MLS_REMOVAL_PENDING refuses a Commit competing with someone's pending
// Remove Commit; the remover's own stored Remove Commit is answered with
// CHAT_MLS_REMOVAL_IN_PROGRESS instead (MLSCommitNeverDiscardCodes). The
// Keeper cannot see the server's log, so the caller (the App) must read the
// handshake log and find no row at expected_epoch + 1 before it asks for a
// discard. Anything else, a lost or unreadable answer, 5xx, 429,
// CHAT_MLS_EPOCH_STALE, keeps the Commit pending for the
// check-log-then-resend path. Sorted.
var MLSCommitDiscardRefusedDefinitiveCodes = []string{
	"CHAT_ACCESS_DENIED",
	"CHAT_MLS_MEMBER_SET_STALE",
	"CHAT_MLS_REMOVAL_PENDING",
	"CHAT_ROOM_MEMBER_LIMIT",
	"CHAT_ROOM_OWNER_LEAVING",
	"CHAT_ROOM_ROLE_REQUIRED",
	"CHAT_SELF_REMOVE_REFUSED",
}

// MLSCommitNeverDiscardCodes are server answers to a Commit post that mean
// the server holds, or may yet take, this Commit: CHAT_MLS_REMOVAL_IN_PROGRESS
// (the remover's own Remove Commit is stored and the server applies it when
// its wait ends) and CHAT_MLS_EPOCH_STALE (another Commit took the epoch; the
// log decides). Dropping such a Commit could fork this device off the group,
// so Validate refuses these codes before the allowed list is consulted, and
// a code never sits in both lists (pinned by test).
var MLSCommitNeverDiscardCodes = []string{
	"CHAT_MLS_EPOCH_STALE",
	"CHAT_MLS_REMOVAL_IN_PROGRESS",
}

// MLSCommitDiscardRefusedRequest drops this device's own pending Commit after
// the server definitively refused it and the handshake log showed no row at
// expected_epoch + 1.
type MLSCommitDiscardRefusedRequest struct {
	Permit         ChatStatePermit `json:"permit"`
	OrgID          string          `json:"org_id"`
	ConversationID string          `json:"conversation_id"`
	ClientCommitID string          `json:"client_commit_id"`
	ExpectedEpoch  uint64          `json:"expected_epoch"`
	RefusalCode    string          `json:"refusal_code"`
}

func (r MLSCommitDiscardRefusedRequest) ChatStateContext() (ChatStatePermit, string, string) {
	return r.Permit, r.OrgID, r.ConversationID
}

func (r MLSCommitDiscardRefusedRequest) Validate() error {
	if err := validateChatStateContext(r.Permit, r.OrgID, r.ConversationID); err != nil {
		return err
	}
	if err := requireMessageUUID(r.ClientCommitID, "client_commit_id"); err != nil {
		return err
	}
	// Epoch 0 is a create, which mls_group_discard_unaccepted drops.
	if r.ExpectedEpoch < 1 {
		return newValidationError("expected_epoch", "must be a positive epoch")
	}
	if slices.Contains(MLSCommitNeverDiscardCodes, r.RefusalCode) {
		return newValidationError("refusal_code", "the server holds or may take this Commit; never a discard reason")
	}
	if !slices.Contains(MLSCommitDiscardRefusedDefinitiveCodes, r.RefusalCode) {
		return newValidationError("refusal_code", "must be a definitive Commit refusal")
	}
	return nil
}

// MLSCommitDiscardRefusedResponseData — the record generation after the
// write. The confirmed epoch is unchanged.
type MLSCommitDiscardRefusedResponseData struct {
	Discarded  bool   `json:"discarded"`
	Generation uint64 `json:"generation"`
}
