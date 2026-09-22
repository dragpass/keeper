// chat_state.go — payload models for the chat v2 conversation-state actions.
//
// Like the chat reveal path, the caller describes *which* conversation it
// means and never *how* anything is bound: there is no AAD field, no canonical
// string, and no path. The state file's own sealing context is built inside the
// Keeper from the owner account, the conversation, and the generation.
//
// Validate() here is structural only. Every check that needs state — the
// signature, the permit window, the request/permit binding, whether a position
// was ever reserved — is the handler's or the store's, and runs regardless of
// what Validate accepted.
//
// Contract: dragpass-control-plane docs/security/adr-ratchet-state-storage.md
// S1-S7. Action rationale: actions_chat_state.go.

package proto

import (
	"math"
	"strconv"
	"strings"
)

// Domain error codes for the conversation-state path. They ride in the existing
// envelope's `error_code` field.
const (
	// ChatStateErrorCodeInvalidInput — malformed syntax, wrong size, unknown or
	// duplicate or missing field, or an out-of-range count.
	ChatStateErrorCodeInvalidInput = "CHAT_STATE_INVALID_INPUT"

	// ChatStateErrorCodeNotAuthorized — permit signature, binding, or window
	// failure. One code for all three: which check refused is not something an
	// unauthorized caller gets to learn.
	ChatStateErrorCodeNotAuthorized = "CHAT_STATE_NOT_AUTHORIZED"

	// ChatStateErrorCodeLockTimeout — another process held the conversation
	// longer than the ceiling. Its own code so the caller never has to infer
	// from a generic failure whether proceeding without the lock is an option.
	// It is not.
	ChatStateErrorCodeLockTimeout = "CHAT_STATE_LOCK_TIMEOUT"

	// ChatStateErrorCodeConflict — the state changed between the read and the
	// write inside one locked section, or the named position is already taken
	// by another message. Both mean the write did not happen.
	ChatStateErrorCodeConflict = "CHAT_STATE_CONFLICT"

	// ChatStateErrorCodeRekeyRequired — the stored state is behind the anchor
	// or behind the server's watermark. Sending is locked for this conversation
	// until a new epoch is established. There is no "retry anyway": continuing
	// on a rewound chain is the failure this whole path exists to prevent.
	ChatStateErrorCodeRekeyRequired = "CHAT_STATE_REKEY_REQUIRED"

	// ChatStateErrorCodeNotFound — no outbox entry for that client message id.
	// A retransmission this late is abandoned rather than re-encrypted.
	ChatStateErrorCodeNotFound = "CHAT_STATE_NOT_FOUND"

	// ChatStateErrorCodeStorageFailure — the state directory or the keyring
	// could not be read or written. Nothing was committed.
	ChatStateErrorCodeStorageFailure = "CHAT_STATE_STORAGE_FAILURE"
)

// Wire-shape constants.
const (
	// ChatStatePermitDomain / ChatStatePermitCanonicalVersion — the first two
	// slots of the 10-item conversation-state permit canonical. A separate
	// domain from `dragpass.chat.read`, so a page of read permits cannot also
	// advance a chain, and a state permit cannot open a message.
	ChatStatePermitDomain           = "dragpass.chat.state"
	ChatStatePermitCanonicalVersion = 1

	// ChatStatePermitTTLSeconds — the server fixes
	// `expires_at = issued_at + 300` and the Keeper requires exactly that
	// span, the same rule the read permit follows. A wider window is not a
	// permit this contract issued.
	ChatStatePermitTTLSeconds = 300

	// ChatStateMaxRequestBytes — the largest of these requests carries one
	// 8208-byte ciphertext in Base64 plus fixed context, so 32 KiB is ample and
	// exists to refuse a hostile payload by length before parsing it.
	ChatStateMaxRequestBytes = 32 * 1024

	// ChatStateMaxReserveCount — the ceiling on one reservation. A caller
	// asking for more positions than this is not composing a message. Kept in
	// step with chatstate.MaxReserveCount by a test in the handlers package.
	ChatStateMaxReserveCount = 64
)

// ChatStatePermit is the server's statement that this account may advance this
// conversation's state now, and how far the server has seen the chain get.
//
// WatermarkEpoch / WatermarkNextIndex are the second rollback axis, and they
// are inside the signature rather than beside it on purpose. A watermark
// carried as an ordinary request field could simply be left out by a caller
// that would rather not be checked against it, which is the same as not having
// it. The server is still UNTRUSTED: the Keeper follows whichever of the
// server's watermark and its own anchor is *higher*, so a server reporting a
// lower one changes nothing and a server reporting a higher one can force a
// re-establishment but learns no plaintext.
type ChatStatePermit struct {
	AccountID          string `json:"account_id"` // from the user JWT, never from the request
	OrgID              string `json:"org_id"`
	ConversationID     string `json:"conversation_id"`
	WatermarkEpoch     uint64 `json:"watermark_epoch"`
	WatermarkNextIndex uint64 `json:"watermark_next_index"`
	IssuedAt           int64  `json:"issued_at"`
	ExpiresAt          int64  `json:"expires_at"` // issued_at + 300
	ServerKeyVersion   uint   `json:"server_key_version"`
	Signature          string `json:"signature"` // Base64, RSA-PSS SHA-256 over the canonical
}

func (p ChatStatePermit) Validate() error {
	if err := requireMessageUUID(p.AccountID, "permit.account_id"); err != nil {
		return err
	}
	if err := requireMessageUUID(p.OrgID, "permit.org_id"); err != nil {
		return err
	}
	if err := requireMessageUUID(p.ConversationID, "permit.conversation_id"); err != nil {
		return err
	}
	if err := requireMessageTimestamp(p.IssuedAt, "permit.issued_at"); err != nil {
		return err
	}
	if err := requireMessageTimestamp(p.ExpiresAt, "permit.expires_at"); err != nil {
		return err
	}
	if p.ServerKeyVersion < 1 || p.ServerKeyVersion > math.MaxUint32 {
		return newValidationError("permit.server_key_version", "must be a positive uint32")
	}
	if _, err := requireBase64(p.Signature, "permit.signature"); err != nil {
		return err
	}
	return nil
}

// ChatStatePermitCanonical builds the 10-item string the server signs and the
// Keeper verifies. No trailing newline; the schema slot is always 1.
//
// Pure function on purpose, like the other canonicals in this package: ariadne
// has to produce these bytes exactly.
func ChatStatePermitCanonical(p ChatStatePermit) string {
	return strings.Join([]string{
		ChatStatePermitDomain,
		strconv.Itoa(ChatStatePermitCanonicalVersion),
		p.AccountID,
		p.OrgID,
		p.ConversationID,
		strconv.FormatUint(p.WatermarkEpoch, 10),
		strconv.FormatUint(p.WatermarkNextIndex, 10),
		strconv.FormatInt(p.IssuedAt, 10),
		strconv.FormatInt(p.ExpiresAt, 10),
		strconv.FormatUint(uint64(p.ServerKeyVersion), 10),
	}, "|")
}

// ChatStateBound is what the four permit-gated requests have in common: a
// conversation, and a permit the handler has to check against it. The three
// fields are repeated on each request rather than embedded because the strict
// decoder derives its required-key set by reflecting over a struct's own
// fields, and an embedded struct's promoted fields are not in that set — a
// `permit` that went missing from a signature-bound request would decode to a
// zero value instead of being refused.
type ChatStateBound interface {
	Validator
	ChatStateContext() (permit ChatStatePermit, orgID, conversationID string)
}

func validateChatStateContext(p ChatStatePermit, orgID, conversationID string) error {
	if err := p.Validate(); err != nil {
		return err
	}
	if err := requireMessageUUID(orgID, "org_id"); err != nil {
		return err
	}
	return requireMessageUUID(conversationID, "conversation_id")
}

// ChatStateReserveSendRequest asks for Count chain positions.
type ChatStateReserveSendRequest struct {
	Permit         ChatStatePermit `json:"permit"`
	OrgID          string          `json:"org_id"`
	ConversationID string          `json:"conversation_id"`
	Count          int             `json:"count"`
}

func (r ChatStateReserveSendRequest) ChatStateContext() (ChatStatePermit, string, string) {
	return r.Permit, r.OrgID, r.ConversationID
}

func (r ChatStateReserveSendRequest) Validate() error {
	if err := validateChatStateContext(r.Permit, r.OrgID, r.ConversationID); err != nil {
		return err
	}
	if r.Count < 1 || r.Count > ChatStateMaxReserveCount {
		return newValidationError("count",
			"must be an integer in 1.."+strconv.Itoa(ChatStateMaxReserveCount))
	}
	return nil
}

type ChatStateReserveSendResponseData struct {
	Epoch           uint64 `json:"epoch"`
	FirstChainIndex uint64 `json:"first_chain_index"`
	Count           int    `json:"count"`
	Generation      uint64 `json:"generation"`
}

// ChatStateCommitOutboxRequest hands the Keeper the ciphertext built for a
// position it already reserved. The ciphertext is public material — it is what
// goes on the wire — so nothing here is a raw-secret field.
type ChatStateCommitOutboxRequest struct {
	Permit          ChatStatePermit `json:"permit"`
	OrgID           string          `json:"org_id"`
	ConversationID  string          `json:"conversation_id"`
	ClientMessageID string          `json:"client_message_id"`
	Epoch           uint64          `json:"epoch"`
	ChainIndex      uint64          `json:"chain_index"`
	IVB64           string          `json:"iv_b64"`
	CiphertextB64   string          `json:"ciphertext_b64"`
}

func (r ChatStateCommitOutboxRequest) ChatStateContext() (ChatStatePermit, string, string) {
	return r.Permit, r.OrgID, r.ConversationID
}

func (r ChatStateCommitOutboxRequest) Validate() error {
	if err := validateChatStateContext(r.Permit, r.OrgID, r.ConversationID); err != nil {
		return err
	}
	if err := requireMessageUUID(r.ClientMessageID, "client_message_id"); err != nil {
		return err
	}
	if err := requireMessageBase64Len(
		r.IVB64, "iv_b64", ConversationIVBytes, ConversationIVBytes,
	); err != nil {
		return err
	}
	return requireMessageBase64Len(
		r.CiphertextB64, "ciphertext_b64",
		ConversationCiphertextMinBytes, ConversationCiphertextMaxBytes,
	)
}

// ChatStateCommitOutboxResponseData echoes the authoritative entry. Stored is
// false when an entry for this client message id already existed, in which case
// the other fields are what was already stored, not what the request carried —
// that difference is the whole retransmission rule.
type ChatStateCommitOutboxResponseData struct {
	Stored        bool   `json:"stored"`
	Epoch         uint64 `json:"epoch"`
	ChainIndex    uint64 `json:"chain_index"`
	IVB64         string `json:"iv_b64"`
	CiphertextB64 string `json:"ciphertext_b64"`
}

type ChatStateReadOutboxRequest struct {
	Permit          ChatStatePermit `json:"permit"`
	OrgID           string          `json:"org_id"`
	ConversationID  string          `json:"conversation_id"`
	ClientMessageID string          `json:"client_message_id"`
}

func (r ChatStateReadOutboxRequest) ChatStateContext() (ChatStatePermit, string, string) {
	return r.Permit, r.OrgID, r.ConversationID
}

func (r ChatStateReadOutboxRequest) Validate() error {
	if err := validateChatStateContext(r.Permit, r.OrgID, r.ConversationID); err != nil {
		return err
	}
	return requireMessageUUID(r.ClientMessageID, "client_message_id")
}

type ChatStateReadOutboxResponseData struct {
	Epoch         uint64 `json:"epoch"`
	ChainIndex    uint64 `json:"chain_index"`
	IVB64         string `json:"iv_b64"`
	CiphertextB64 string `json:"ciphertext_b64"`
}

type ChatStateMarkReceivedRequest struct {
	Permit         ChatStatePermit `json:"permit"`
	OrgID          string          `json:"org_id"`
	ConversationID string          `json:"conversation_id"`
	Epoch          uint64          `json:"epoch"`
	ChainIndex     uint64          `json:"chain_index"`
}

func (r ChatStateMarkReceivedRequest) ChatStateContext() (ChatStatePermit, string, string) {
	return r.Permit, r.OrgID, r.ConversationID
}

func (r ChatStateMarkReceivedRequest) Validate() error {
	return validateChatStateContext(r.Permit, r.OrgID, r.ConversationID)
}

type ChatStateMarkReceivedResponseData struct {
	FirstDelivery bool   `json:"first_delivery"`
	Generation    uint64 `json:"generation"`
}

// ChatStatePurgeRequest names the account whose state goes away. No permit: see
// actions_chat_state.go.
type ChatStatePurgeRequest struct {
	OwnerAccountID string `json:"owner_account_id"`
}

func (r ChatStatePurgeRequest) Validate() error {
	return requireMessageUUID(r.OwnerAccountID, "owner_account_id")
}

type ChatStatePurgeResponseData struct {
	RemovedConversations int `json:"removed_conversations"`
}
