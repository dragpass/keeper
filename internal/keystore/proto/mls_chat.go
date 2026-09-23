// mls_chat.go — payload models for the MLS chat v2 actions.
//
// Every request here is a conversation-state request: it carries the same
// ChatStatePermit (canonical v3) as the chat_state_* actions and implements
// ChatStateBound, so the handlers run the one gate authorizeChatState already
// runs. What differs is the size cap, because a KeyPackage batch, a Commit and
// a Welcome are larger than one ciphertext.
//
// As in chat_state.go, Validate is structural only and there is no field that
// says how anything is bound: no AAD, no group id, no leaf index the caller
// picks. The group is named by the conversation, the leaf by the device's own
// key, and every position by the MLS state.
//
// Action rationale: actions_mls_chat.go. Design: dragpass-control-plane
// docs/exec-plans/active/dragpass-chat-v2-mls-integration.md §12.2.

package proto

import (
	"strconv"
)

// Domain error codes the MLS actions add. They ride in the envelope's
// `error_code` field next to the ChatState* and ChatMLS* codes in
// chat_state.go.
const (
	// ChatMLSErrorCodeCommitPending — this device has a Commit whose CAS
	// outcome it has not been told (design §7.3.2). A new Commit, a new send
	// and a new MLS open are refused until mls_commit_confirm settles it;
	// a retransmission and a history re-read are not.
	ChatMLSErrorCodeCommitPending = "CHAT_MLS_COMMIT_PENDING"

	// ChatMLSErrorCodeEpochStale — the request does not continue this device's
	// confirmed epoch: a send or Commit built for another epoch than the one
	// the group is on, or a handshake that is already applied or comes after
	// one that is not. The server answers its own CAS failure with the same
	// code; this is the Keeper-side meaning.
	ChatMLSErrorCodeEpochStale = "CHAT_MLS_EPOCH_STALE"

	// ChatMLSErrorCodeFailed — the MLS operation itself failed or refused: a
	// message that does not open, a declaration that does not match the
	// position, a Welcome for another conversation, a group state that does
	// not exist yet. Nothing was written.
	ChatMLSErrorCodeFailed = "CHAT_MLS_FAILED"

	// ChatMLSErrorCodeWelcomeUnusable — this device holds no private keys for
	// any KeyPackage the Welcome is addressed to: the KeyPackage expired, was
	// already used, or belonged to a leaf a promote has since replaced. The
	// invitation cannot be used on this device, and retrying cannot change
	// that; the member has to be invited again with a KeyPackage of the
	// current leaf. Nothing was written and the pool is unchanged.
	ChatMLSErrorCodeWelcomeUnusable = "CHAT_MLS_WELCOME_UNUSABLE"
)

// Wire-shape constants. The ones that mirror a bound elsewhere are kept in
// step with it by a test in the handlers package, which can import both.
const (
	// MLSChatMaxMembersPerCommit mirrors mls.MaxKeyPackagesPerCall.
	MLSChatMaxMembersPerCommit = 32

	// MLSChatMaxKeyPackageBytes mirrors mls.MaxKeyPackageBytes, the largest
	// KeyPackage the server stores.
	MLSChatMaxKeyPackageBytes = 8192

	// MLSChatMaxCommitBytes mirrors chatstate.MaxCommitBytes, the bound on a
	// Commit and a Welcome.
	MLSChatMaxCommitBytes = 262144

	// MLSChatMaxRemoveAccounts bounds one Remove Commit. ariadne caps a room at
	// 30 members; the ceiling matches ChatStateMaxPendingRemovals.
	MLSChatMaxRemoveAccounts = ChatStateMaxPendingRemovals

	// MLSChatMaxRequestBytes is the cap for the membership and handshake
	// actions: 32 KeyPackages of 8192 bytes, or one 256 KiB Commit or
	// Welcome, in Base64, plus rotation chains and fixed context.
	MLSChatMaxRequestBytes = 1024 * 1024

	// MLSEncryptMaxPlaintextBytes bounds one application message. The
	// ciphertext has to fit the 8208 bytes the server's message column and
	// chatstate.MaxCiphertextBytes allow, and MLS adds the sender's signature,
	// the framing, the declaration and the AEAD tag, then pads with the
	// StepFunction rule (the top three bits of the length survive, so up to
	// an eighth more). 6144 bytes pads to at most 7168 and leaves the rest for
	// the overhead; a test in dispatch encrypts one of exactly this size.
	MLSEncryptMaxPlaintextBytes = 6144

	// MLSDecryptMaxMessages is the display batch, the same 200 as the v1
	// reveal.
	MLSDecryptMaxMessages = ConversationDecryptMaxMessages

	// MLSDecryptMaxRequestBytes fits 200 ciphertexts of 8208 bytes in Base64
	// plus fixed context. The v1 reveal's 2 MiB does not.
	MLSDecryptMaxRequestBytes = 3 * 1024 * 1024
)

// MLS commit outcomes a caller reports to mls_commit_confirm.
const (
	MLSCommitOutcomeAccepted   = "accepted"
	MLSCommitOutcomeSuperseded = "superseded"
	MLSCommitOutcomeUnknown    = "unknown"
)

// MLSMemberKeyPackage is one member to Add: the KeyPackage the server handed
// out, and the account and device the caller asked it for. The Keeper refuses
// a KeyPackage whose credential names anyone else, which §5.3 alone cannot
// catch: a server that answers a request for Bob with Mallory's valid
// KeyPackage passes every check a leaf is put through.
type MLSMemberKeyPackage struct {
	AccountID     string `json:"account_id"`
	DeviceID      string `json:"device_id"`
	KeyPackageB64 string `json:"key_package_b64"`
}

func (m MLSMemberKeyPackage) Validate() error {
	if err := requireMessageUUID(m.AccountID, "members.account_id"); err != nil {
		return err
	}
	if err := requireMessageUUID(m.DeviceID, "members.device_id"); err != nil {
		return err
	}
	return requireMessageBase64Len(m.KeyPackageB64, "members.key_package_b64", 1, MLSChatMaxKeyPackageBytes)
}

func validateMLSMembers(members []MLSMemberKeyPackage, field string) error {
	if len(members) == 0 || len(members) > MLSChatMaxMembersPerCommit {
		return newValidationError(field,
			"must hold 1.."+strconv.Itoa(MLSChatMaxMembersPerCommit)+" members")
	}
	seen := map[string]bool{}
	for _, m := range members {
		if err := m.Validate(); err != nil {
			return err
		}
		if seen[m.AccountID+"|"+m.DeviceID] {
			return newValidationError(field, "must not name one device twice")
		}
		seen[m.AccountID+"|"+m.DeviceID] = true
	}
	return nil
}

// MLSCommitResponseData is what mls_group_create and mls_commit_build hand
// back: the bytes to post to POST /:id/mls/commit. The Commit is pending and
// nothing about the confirmed state moved. WelcomeReleasable is always false
// here (RFC 9420 §14): the Welcome travels to the server with the Commit in
// one row and is served to a joiner only once that row won its epoch.
type MLSCommitResponseData struct {
	ClientCommitID string `json:"client_commit_id"`

	// ExpectedEpoch is the confirmed epoch the Commit was built against, the
	// value the server's CAS compares.
	ExpectedEpoch uint64 `json:"expected_epoch"`
	CommitB64     string `json:"commit_b64"`

	// WelcomeB64 is empty when the Commit adds nobody.
	WelcomeB64        string `json:"welcome_b64"`
	WelcomeReleasable bool   `json:"welcome_releasable"`

	// Created is false when the answer came from a Commit already pending
	// under the same client_commit_id: a lost response retried, not rebuilt.
	Created    bool   `json:"created"`
	Generation uint64 `json:"generation"`
}

// MLSGroupCreateRequest creates the conversation's group at epoch 0 and builds
// the Add for its first members. The caller is not in Members.
type MLSGroupCreateRequest struct {
	Permit             ChatStatePermit        `json:"permit"`
	OrgID              string                 `json:"org_id"`
	ConversationID     string                 `json:"conversation_id"`
	ClientCommitID     string                 `json:"client_commit_id"`
	Members            []MLSMemberKeyPackage  `json:"members"`
	RotationStatements []KeyRotationStatement `json:"rotation_statements,omitempty"`
}

func (r MLSGroupCreateRequest) ChatStateContext() (ChatStatePermit, string, string) {
	return r.Permit, r.OrgID, r.ConversationID
}

func (r MLSGroupCreateRequest) Validate() error {
	if err := validateChatStateContext(r.Permit, r.OrgID, r.ConversationID); err != nil {
		return err
	}
	if err := requireMessageUUID(r.ClientCommitID, "client_commit_id"); err != nil {
		return err
	}
	if err := validateMLSMembers(r.Members, "members"); err != nil {
		return err
	}
	return ValidateKeyRotationStatements(r.RotationStatements)
}

// MLSCommitBuildRequest builds one Commit of exactly one kind: an Add, a
// Remove of every leaf of the named accounts, or an Update of this device's
// own leaf. UpdateSelf also moves the group onto the device's active leaf key
// when a rotation has promoted a new one (design P3).
type MLSCommitBuildRequest struct {
	Permit           ChatStatePermit       `json:"permit"`
	OrgID            string                `json:"org_id"`
	ConversationID   string                `json:"conversation_id"`
	ClientCommitID   string                `json:"client_commit_id"`
	ExpectedEpoch    uint64                `json:"expected_epoch"`
	Add              []MLSMemberKeyPackage `json:"add,omitempty"`
	RemoveAccountIDs []string              `json:"remove_account_ids,omitempty"`
	UpdateSelf       bool                  `json:"update_self,omitempty"`

	RotationStatements []KeyRotationStatement `json:"rotation_statements,omitempty"`
}

func (r MLSCommitBuildRequest) ChatStateContext() (ChatStatePermit, string, string) {
	return r.Permit, r.OrgID, r.ConversationID
}

func (r MLSCommitBuildRequest) Validate() error {
	if err := validateChatStateContext(r.Permit, r.OrgID, r.ConversationID); err != nil {
		return err
	}
	if err := requireMessageUUID(r.ClientCommitID, "client_commit_id"); err != nil {
		return err
	}
	// Epoch 0 is a group whose creating Add is still pending, and a pending
	// Commit refuses another; nothing is ever built against it. Requiring a
	// positive value also keeps the assertion from being skipped by a zero.
	if r.ExpectedEpoch < 1 {
		return newValidationError("expected_epoch", "must be a positive epoch")
	}
	kinds := 0
	if r.Add != nil {
		kinds++
		if err := validateMLSMembers(r.Add, "add"); err != nil {
			return err
		}
	}
	if r.RemoveAccountIDs != nil {
		kinds++
		if err := validateRemoveAccounts(r.RemoveAccountIDs); err != nil {
			return err
		}
	}
	if r.UpdateSelf {
		kinds++
	}
	if kinds != 1 {
		return newValidationError("add",
			"exactly one of add, remove_account_ids and update_self must be given")
	}
	return ValidateKeyRotationStatements(r.RotationStatements)
}

func validateRemoveAccounts(ids []string) error {
	const field = "remove_account_ids"
	if len(ids) == 0 || len(ids) > MLSChatMaxRemoveAccounts {
		return newValidationError(field,
			"must hold 1.."+strconv.Itoa(MLSChatMaxRemoveAccounts)+" account ids")
	}
	seen := map[string]bool{}
	for _, id := range ids {
		if err := requireMessageUUID(id, field); err != nil {
			return err
		}
		if seen[id] {
			return newValidationError(field, "must not name one account twice")
		}
		seen[id] = true
	}
	return nil
}

// MLSCommitConfirmRequest reports what the server's CAS said about a Commit
// this device built. Outcome is accepted, superseded (another Commit won the
// epoch; WinnerCommitB64 is that Commit), or unknown (the response was lost
// and the caller is about to ask the server by client_commit_id). Unknown
// writes nothing and answers with the bytes to repost.
type MLSCommitConfirmRequest struct {
	Permit          ChatStatePermit `json:"permit"`
	OrgID           string          `json:"org_id"`
	ConversationID  string          `json:"conversation_id"`
	ClientCommitID  string          `json:"client_commit_id"`
	Outcome         string          `json:"outcome"`
	WinnerCommitB64 string          `json:"winner_commit_b64,omitempty"`

	RotationStatements []KeyRotationStatement `json:"rotation_statements,omitempty"`
}

func (r MLSCommitConfirmRequest) ChatStateContext() (ChatStatePermit, string, string) {
	return r.Permit, r.OrgID, r.ConversationID
}

func (r MLSCommitConfirmRequest) Validate() error {
	if err := validateChatStateContext(r.Permit, r.OrgID, r.ConversationID); err != nil {
		return err
	}
	if err := requireMessageUUID(r.ClientCommitID, "client_commit_id"); err != nil {
		return err
	}
	switch r.Outcome {
	case MLSCommitOutcomeSuperseded:
		if err := requireMessageBase64Len(
			r.WinnerCommitB64, "winner_commit_b64", 1, MLSChatMaxCommitBytes,
		); err != nil {
			return err
		}
	case MLSCommitOutcomeAccepted, MLSCommitOutcomeUnknown:
		if r.WinnerCommitB64 != "" {
			return newValidationError("winner_commit_b64", "is only for a superseded outcome")
		}
	default:
		return newValidationError("outcome", "must be "+MLSCommitOutcomeAccepted+", "+
			MLSCommitOutcomeSuperseded+" or "+MLSCommitOutcomeUnknown)
	}
	return ValidateKeyRotationStatements(r.RotationStatements)
}

// MLSCommitConfirmResponseData is the state after the verdict. For accepted
// and superseded, Epoch is the new confirmed epoch; for unknown it is the one
// the pending Commit was built against, and CommitB64 is that Commit, to be
// reposted under the same client_commit_id if the server has no record of it.
type MLSCommitConfirmResponseData struct {
	Outcome           string `json:"outcome"`
	Epoch             uint64 `json:"epoch"`
	WelcomeReleasable bool   `json:"welcome_releasable"`
	Removed           bool   `json:"removed"`
	CommitB64         string `json:"commit_b64"`
	Generation        uint64 `json:"generation"`
}

// MLSProcessRequest applies one handshake row from GET /:id/mls/handshake:
// somebody else's Commit. Epoch is the row's epoch, the one the Commit
// produced; the Keeper applies rows only in epoch order and checks the claim
// against what the Commit really produced.
type MLSProcessRequest struct {
	Permit         ChatStatePermit `json:"permit"`
	OrgID          string          `json:"org_id"`
	ConversationID string          `json:"conversation_id"`
	Seq            uint64          `json:"seq"`
	Epoch          uint64          `json:"epoch"`
	CommitB64      string          `json:"commit_b64"`

	RotationStatements []KeyRotationStatement `json:"rotation_statements,omitempty"`
}

func (r MLSProcessRequest) ChatStateContext() (ChatStatePermit, string, string) {
	return r.Permit, r.OrgID, r.ConversationID
}

func (r MLSProcessRequest) Validate() error {
	if err := validateChatStateContext(r.Permit, r.OrgID, r.ConversationID); err != nil {
		return err
	}
	if r.Seq < 1 {
		return newValidationError("seq", "must be a positive sequence")
	}
	if r.Epoch < 1 {
		return newValidationError("epoch", "must be a positive epoch")
	}
	if err := requireMessageBase64Len(r.CommitB64, "commit_b64", 1, MLSChatMaxCommitBytes); err != nil {
		return err
	}
	return ValidateKeyRotationStatements(r.RotationStatements)
}

type MLSProcessResponseData struct {
	Seq        uint64 `json:"seq"`
	Epoch      uint64 `json:"epoch"`
	Removed    bool   `json:"removed"`
	Generation uint64 `json:"generation"`
}

// MLSJoinRequest joins the conversation's group from a Welcome addressed to
// one of this device's KeyPackages.
type MLSJoinRequest struct {
	Permit         ChatStatePermit `json:"permit"`
	OrgID          string          `json:"org_id"`
	ConversationID string          `json:"conversation_id"`
	WelcomeB64     string          `json:"welcome_b64"`

	RotationStatements []KeyRotationStatement `json:"rotation_statements,omitempty"`
}

func (r MLSJoinRequest) ChatStateContext() (ChatStatePermit, string, string) {
	return r.Permit, r.OrgID, r.ConversationID
}

func (r MLSJoinRequest) Validate() error {
	if err := validateChatStateContext(r.Permit, r.OrgID, r.ConversationID); err != nil {
		return err
	}
	if err := requireMessageBase64Len(r.WelcomeB64, "welcome_b64", 1, MLSChatMaxCommitBytes); err != nil {
		return err
	}
	return ValidateKeyRotationStatements(r.RotationStatements)
}

type MLSJoinResponseData struct {
	Epoch uint64 `json:"epoch"`
}

// MLSEncryptRequest encrypts one application message: reserve, encrypt and
// persist in one locked section (design §7.2.1 T-c). client_message_id is the
// outbox key: a second call with it answers with the stored ciphertext and
// encrypts nothing.
type MLSEncryptRequest struct {
	Permit          ChatStatePermit `json:"permit"`
	OrgID           string          `json:"org_id"`
	ConversationID  string          `json:"conversation_id"`
	ClientMessageID string          `json:"client_message_id"`
	ExpectedEpoch   uint64          `json:"expected_epoch"`
	PlaintextB64    string          `json:"plaintext_b64"` // encrypt direction; zeroized after sealing, never logged
}

func (r MLSEncryptRequest) ChatStateContext() (ChatStatePermit, string, string) {
	return r.Permit, r.OrgID, r.ConversationID
}

func (r MLSEncryptRequest) Validate() error {
	if err := validateChatStateContext(r.Permit, r.OrgID, r.ConversationID); err != nil {
		return err
	}
	if err := requireMessageUUID(r.ClientMessageID, "client_message_id"); err != nil {
		return err
	}
	// Nothing is ever sent at epoch 0, where the creator is alone and its Add
	// is pending; a positive value also keeps the assertion from being
	// skipped by a zero.
	if r.ExpectedEpoch < 1 {
		return newValidationError("expected_epoch", "must be a positive epoch")
	}
	return requireMessageBase64Len(r.PlaintextB64, "plaintext_b64", 1, MLSEncryptMaxPlaintextBytes)
}

// MLSEncryptResponseData is what POST /:id/messages needs: the ciphertext, and
// the position the library actually used, which the sender declares for the
// W2 watermark. The caller does not pick the position; only the group state
// knows it. Generation here is the step along this sender's application
// ratchet, not the record's write counter.
type MLSEncryptResponseData struct {
	ClientMessageID string `json:"client_message_id"`
	CiphertextB64   string `json:"ciphertext_b64"`
	Epoch           uint64 `json:"epoch"`
	LeafIndex       uint32 `json:"leaf_index"`
	ContentType     string `json:"content_type"`
	Generation      uint64 `json:"generation"`

	// Created is false when the stored ciphertext for this client_message_id
	// answered: a retransmission sends the same bytes.
	Created bool `json:"created"`
}

// MLSDisplayMessage is one message of a display batch: the server's seq and
// the MLS PrivateMessage it stored.
type MLSDisplayMessage struct {
	Seq           uint64 `json:"seq"`
	CiphertextB64 string `json:"ciphertext_b64"`
}

// MLSDecryptBatchForAppDisplayRequest opens a page of one conversation's
// messages for display. It answers with the v1 reveal's response type, widened
// (ConversationDecryptBatchForAppDisplayResponseData.items): one carve-out,
// not a third (design M6.3).
type MLSDecryptBatchForAppDisplayRequest struct {
	Permit         ChatStatePermit     `json:"permit"`
	OrgID          string              `json:"org_id"`
	ConversationID string              `json:"conversation_id"`
	Messages       []MLSDisplayMessage `json:"messages"`
}

func (r MLSDecryptBatchForAppDisplayRequest) ChatStateContext() (ChatStatePermit, string, string) {
	return r.Permit, r.OrgID, r.ConversationID
}

func (r MLSDecryptBatchForAppDisplayRequest) Validate() error {
	if err := validateChatStateContext(r.Permit, r.OrgID, r.ConversationID); err != nil {
		return err
	}
	if len(r.Messages) == 0 || len(r.Messages) > MLSDecryptMaxMessages {
		return newValidationError("messages",
			"must hold 1.."+strconv.Itoa(MLSDecryptMaxMessages)+" entries")
	}
	seen := make(map[uint64]bool, len(r.Messages))
	for _, m := range r.Messages {
		if m.Seq < 1 {
			return newValidationError("messages.seq", "must be a positive sequence")
		}
		if seen[m.Seq] {
			return newValidationError("messages.seq", "must not repeat within a batch")
		}
		seen[m.Seq] = true
		if err := requireMessageBase64Len(
			m.CiphertextB64, "messages.ciphertext_b64", 1, ConversationCiphertextMaxBytes,
		); err != nil {
			return err
		}
	}
	return nil
}

// MLSDisplayItem is what the app may show about one decrypted message besides
// its plaintext, parallel to plaintext_b64. The sender comes from the leaf
// credential MLS authenticated, never from the server; epoch, leaf, axis and
// generation are the position the declaration was checked against.
// FromHistory is true when the plaintext came from this device's sealed local
// copy and no MLS key was used.
type MLSDisplayItem struct {
	Seq             uint64 `json:"seq"`
	SenderAccountID string `json:"sender_account_id"`
	SenderDeviceID  string `json:"sender_device_id"`
	Epoch           uint64 `json:"epoch"`
	SenderLeafIndex uint32 `json:"sender_leaf_index"`
	ContentType     string `json:"content_type"`
	Generation      uint64 `json:"generation"`
	FromHistory     bool   `json:"from_history"`
}

// MLSConversationStatusRequest asks where this device's copy of the
// conversation stands. Read-only.
type MLSConversationStatusRequest struct {
	Permit         ChatStatePermit `json:"permit"`
	OrgID          string          `json:"org_id"`
	ConversationID string          `json:"conversation_id"`
}

func (r MLSConversationStatusRequest) ChatStateContext() (ChatStatePermit, string, string) {
	return r.Permit, r.OrgID, r.ConversationID
}

func (r MLSConversationStatusRequest) Validate() error {
	return validateChatStateContext(r.Permit, r.OrgID, r.ConversationID)
}

// MLSConversationStatusResponseData lets the app say "참여자 변경 반영 중"
// before it tries to send, rather than after a refusal. RemovalLatch is the
// accounts a send would be refused for now (CHAT_MLS_ROTATION_PENDING), judged
// on the confirmed roster against this permit's list; empty, never null. When
// NeedsRekey is true the record is latched for a rewind and the other fields
// are zero: nothing behind the latch is trusted to say anything.
type MLSConversationStatusResponseData struct {
	Epoch                 uint64   `json:"epoch"`
	HasGroupState         bool     `json:"has_group_state"`
	CommitPending         bool     `json:"commit_pending"`
	PendingClientCommitID string   `json:"pending_client_commit_id"`
	RemovalLatch          []string `json:"removal_latch_account_ids"`
	NeedsRekey            bool     `json:"needs_rekey"`
}
