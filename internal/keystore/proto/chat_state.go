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

	// ChatMLSErrorCodeLeafUntrusted — a leaf that would enter the group is
	// not vouched for by its account: no declaration, a malformed one, a bad
	// signature, a declaration for another account, device or key, a
	// superseded declaration, or an account whose key the pin reports as
	// changed (design §5.3, §13). Nothing was applied and nothing was
	// recorded. There is no "ignore and continue".
	ChatMLSErrorCodeLeafUntrusted = "CHAT_MLS_LEAF_UNTRUSTED"

	// ChatMLSErrorCodeCapabilityRequired — this Keeper binary was built
	// without the MLS library (design §13).
	ChatMLSErrorCodeCapabilityRequired = "CHAT_MLS_CAPABILITY_REQUIRED"

	// ChatMLSErrorCodeRotationPending — a permit has named an account this
	// device's confirmed group still holds a leaf for as removed from the
	// organization, and this device has not yet applied a Commit that takes
	// that leaf out (design §6.4.1 S-1). New application messages in the
	// conversation are refused; receiving and Commits are not. The same code
	// the server answers POST /:id/messages with, because the server refusing
	// alone means nothing under a server that is not honest.
	ChatMLSErrorCodeRotationPending = "CHAT_MLS_ROTATION_PENDING"

	// ChatMLSErrorCodeLeafReplacementPending — a permit has named an account
	// as taken over by a new device (design M4.4), and this device's confirmed
	// group still holds a leaf of that account under another key. The old
	// device may be lost or stolen and its leaf holds the current epoch keys,
	// so new application messages are refused until a replace Commit that
	// takes that leaf out is confirmed here. Receiving and Commits are not
	// refused.
	ChatMLSErrorCodeLeafReplacementPending = "CHAT_MLS_LEAF_REPLACEMENT_PENDING"
)

// Wire-shape constants.
const (
	// ChatStatePermitDomain / ChatStatePermitCanonicalVersion — the first two
	// slots of the 14-item conversation-state permit canonical.
	ChatStatePermitDomain           = "dragpass.chat.state"
	ChatStatePermitCanonicalVersion = 4

	// ChatStateMaxPendingRemovals bounds pending_removal_account_ids. ariadne
	// caps a room at 30 members, so an honest list is far below this; a longer
	// one is refused rather than truncated, because dropping a name is exactly
	// the omission S-1 cannot afford to make on its own.
	ChatStateMaxPendingRemovals = 64

	// ChatStateMaxPendingLeafReplacements bounds pending_leaf_replacements, for
	// the same reason and at the same value as the removal list.
	ChatStateMaxPendingLeafReplacements = ChatStateMaxPendingRemovals

	// ChatStatePermitTTLSeconds — the server fixes
	// `expires_at = issued_at + 300` and the Keeper requires exactly that
	// span. A wider window is not a
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

	// ChatStateContentTypeHandshake / ChatStateContentTypeApplication — which
	// of a sender's two ratchets a received position sits on. Kept in step with
	// the chatstate constants by a test in the handlers package.
	ChatStateContentTypeHandshake   = "handshake"
	ChatStateContentTypeApplication = "application"
)

// ChatStatePermit is the server's statement that this account may advance this
// conversation's state now, and how far the server has seen the chain get.
//
// The four Watermark* fields are the second rollback axis, and they are inside
// the signature rather than beside it on purpose. A watermark carried as an
// ordinary request field could simply be left out by a caller that would rather
// not be checked against it, which is the same as not having it. The server is
// still UNTRUSTED: the Keeper follows whichever of the server's watermark and
// its own anchor is *higher*, so a server reporting a lower one changes nothing
// and a server reporting a higher one can force a re-establishment but learns
// no plaintext.
//
// Four slots rather than one because naming a position in an MLS group takes
// four (chatstate.Position): every sender has its own ratchet and each sender
// has a handshake one and an application one. Only the application axis is
// compared; see chatstate.Anchor.rewound for why the handshake one is carried
// and not looked at.
type ChatStatePermit struct {
	AccountID      string `json:"account_id"` // from the user JWT, never from the request
	OrgID          string `json:"org_id"`
	ConversationID string `json:"conversation_id"`

	WatermarkEpoch uint64 `json:"watermark_epoch"`

	// WatermarkLeafIndex names whose chain the two counters below describe. It
	// carries nothing until the server has accepted a position, and once it
	// has, a permit naming another leaf is refused rather than used to judge
	// this one's chain.
	WatermarkLeafIndex       uint32 `json:"watermark_leaf_index"`
	WatermarkNextHandshake   uint64 `json:"watermark_next_handshake"`
	WatermarkNextApplication uint64 `json:"watermark_next_application"`

	// PendingRemovalAccountIDs is the server's claim of which accounts left
	// the organization and still await a Remove Commit in this conversation
	// (design §6.4.1 S-1). Lowercase UUIDs, ascending, no duplicates, and []
	// when there are none; null is refused. It is only ever a reason to stop
	// encrypting. The Keeper resumes on its own confirmed group state and
	// never because a later permit stopped listing an account.
	PendingRemovalAccountIDs []string `json:"pending_removal_account_ids"`

	// PendingLeafReplacements is the server's claim of which accounts a new
	// device has taken over, and the signature key fingerprint of the leaf
	// that replaces theirs (design M4.4). Ascending by account, one entry per
	// account, and [] when there are none; null is refused. Like the removal
	// list it is only ever a reason to stop encrypting, and it is also the
	// only fingerprint a replace Commit may add for that account.
	PendingLeafReplacements []ChatStateLeafReplacement `json:"pending_leaf_replacements"`

	IssuedAt         int64  `json:"issued_at"`
	ExpiresAt        int64  `json:"expires_at"` // issued_at + 300
	ServerKeyVersion uint   `json:"server_key_version"`
	Signature        string `json:"signature"` // Base64, RSA-PSS SHA-256 over the canonical
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
	if err := validatePendingRemovals(p.PendingRemovalAccountIDs); err != nil {
		return err
	}
	if err := validatePendingLeafReplacements(p.PendingLeafReplacements); err != nil {
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

// validatePendingRemovals refuses a list the canonical would not reproduce
// byte for byte. It never repairs one: sorting or de-duplicating here would
// verify a signature over bytes the server did not sign.
func validatePendingRemovals(ids []string) error {
	const field = "permit.pending_removal_account_ids"
	if ids == nil {
		return newValidationError(field, "must be an array")
	}
	if len(ids) > ChatStateMaxPendingRemovals {
		return newValidationError(field,
			"must hold at most "+strconv.Itoa(ChatStateMaxPendingRemovals)+" account ids")
	}
	for i, id := range ids {
		if err := requireMessageUUID(id, field); err != nil {
			return err
		}
		if i > 0 && ids[i-1] >= id {
			return newValidationError(field, "must be sorted ascending without duplicates")
		}
	}
	return nil
}

// ChatStateLeafReplacement is one entry of pending_leaf_replacements: the
// account a new device took over, and the fingerprint of that device's leaf
// signature key.
type ChatStateLeafReplacement struct {
	AccountID         string `json:"account_id"`
	NewSignatureKeyFP string `json:"new_signature_key_fp"`
}

// validatePendingLeafReplacements holds the list to the same rule as the
// removal list: exactly the bytes the canonical reproduces, never repaired.
// One entry per account, because two fingerprints for one account would be two
// leaves the server claims are both the one that replaces it.
func validatePendingLeafReplacements(entries []ChatStateLeafReplacement) error {
	const field = "permit.pending_leaf_replacements"
	if entries == nil {
		return newValidationError(field, "must be an array")
	}
	if len(entries) > ChatStateMaxPendingLeafReplacements {
		return newValidationError(field,
			"must hold at most "+strconv.Itoa(ChatStateMaxPendingLeafReplacements)+" entries")
	}
	for i, e := range entries {
		if err := requireMessageUUID(e.AccountID, field+".account_id"); err != nil {
			return err
		}
		if err := requireKeyFingerprint(e.NewSignatureKeyFP, field+".new_signature_key_fp"); err != nil {
			return err
		}
		if i > 0 && entries[i-1].AccountID >= e.AccountID {
			return newValidationError(field, "must be sorted ascending by account_id without duplicates")
		}
	}
	return nil
}

// chatStateLeafReplacementsCanonical is the slot's canonical form:
// `<account_id>:<fp>` per entry, joined with ",", and "" for none. Validate
// has already required the order, so this only joins.
func chatStateLeafReplacementsCanonical(entries []ChatStateLeafReplacement) string {
	parts := make([]string, len(entries))
	for i, e := range entries {
		parts[i] = e.AccountID + ":" + e.NewSignatureKeyFP
	}
	return strings.Join(parts, ",")
}

// ChatStatePermitCanonical builds the 14-item string the server signs and the
// Keeper verifies. No trailing newline; the schema slot is always 4.
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
		strconv.FormatUint(uint64(p.WatermarkLeafIndex), 10),
		strconv.FormatUint(p.WatermarkNextHandshake, 10),
		strconv.FormatUint(p.WatermarkNextApplication, 10),
		strings.Join(p.PendingRemovalAccountIDs, ","),
		chatStateLeafReplacementsCanonical(p.PendingLeafReplacements),
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

	// LeafIndex and ContentType complete the position an mls_encrypt entry
	// was sealed at (0.0.55), which is what POST /:id/messages declares. An
	// app that lost mls_encrypt's answer and keeps no plaintext can only post
	// the message from here. A chat_state_commit_outbox entry has neither.
	LeafIndex   uint32 `json:"leaf_index"`
	ContentType string `json:"content_type,omitempty"`
}

// ChatStateMarkReceivedRequest names one inbound position. Four slots and not
// two, because MLS gives every sender its own sender ratchet (RFC 9420 §9.1)
// and gives each sender a handshake one and an application one (§6.3.1):
// (epoch, generation) is not unique in a group, and two members' first messages
// of an epoch would each be judged a redelivery of the other.
type ChatStateMarkReceivedRequest struct {
	Permit          ChatStatePermit `json:"permit"`
	OrgID           string          `json:"org_id"`
	ConversationID  string          `json:"conversation_id"`
	Epoch           uint64          `json:"epoch"`
	SenderLeafIndex uint32          `json:"sender_leaf_index"`
	ContentType     string          `json:"content_type"`
	Generation      uint64          `json:"generation"`
}

func (r ChatStateMarkReceivedRequest) ChatStateContext() (ChatStatePermit, string, string) {
	return r.Permit, r.OrgID, r.ConversationID
}

func (r ChatStateMarkReceivedRequest) Validate() error {
	if err := validateChatStateContext(r.Permit, r.OrgID, r.ConversationID); err != nil {
		return err
	}
	if r.ContentType != ChatStateContentTypeHandshake &&
		r.ContentType != ChatStateContentTypeApplication {
		return newValidationError("content_type",
			"must be "+ChatStateContentTypeHandshake+" or "+ChatStateContentTypeApplication)
	}
	return nil
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
