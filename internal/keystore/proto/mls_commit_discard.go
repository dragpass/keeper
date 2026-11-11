package proto

import "slices"

// MLSCommitDiscardRefusedDefinitiveCodes are the server answers to a Commit
// post that refuse it for good and store nothing (ariadne
// `POST /conversations/:id/mls/commit`). Each is returned after the server
// looked the client_commit_id up and found no stored Commit, so it is never
// the answer to a Commit the server took. Anything else, a lost or unreadable
// answer, 5xx, 429, CHAT_MLS_EPOCH_STALE, keeps the Commit pending for the
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
