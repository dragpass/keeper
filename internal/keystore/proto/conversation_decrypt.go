// conversation_decrypt.go — payload models for the DragPass 1:1 chat reveal
// path (conversation_decrypt_batch_for_app_display).
//
// The request carries the conversation context the Keeper needs to rebuild the
// chat AAD by itself — org_id, conversation_id, dek_version — plus the
// server-signed conversation-read-permit and the batch of sealed messages.
// There is deliberately no aad_b64, no domain, and no canonical field: the
// caller describes *which* conversation this is, never *how* the messages are
// bound. See actions_conversation.go for the security model and
// dragpass-control-plane
// docs/exec-plans/active/dragpass-chat-1to1-implementation.md §4 / §5 for the
// contract these types implement.
//
// Validate() here is structural only — formats, ranges, batch size, and each
// message's decoded length. Everything that needs state (the signature, the
// permit window, the binding against the request, the group handle) is the
// handler's job and is checked there regardless of what Validate accepted.
//
// Unlike the Secure Message reveal there is no per-message challenge: opening
// the group handle from a wrapped grant is itself the key-possession proof, so
// the two axes are (handle = key) + (permit = server authorization). One permit
// opens every message of one conversation at one dek_version inside its TTL.

package proto

import (
	"math"
	"strconv"
	"strings"
)

// Domain error codes for the chat reveal path. Like the message codes they name
// the specific failure the chat surface reacts to, and they travel in the
// existing envelope's `error_code` field. Contract: dragpass-control-plane
// docs/exec-plans/active/dragpass-chat-1to1-implementation.md §3.
const (
	// ChatErrorCodeInvalidInput — malformed syntax, wrong size, unknown or
	// duplicate or missing field, oversize request, or a batch over the cap.
	ChatErrorCodeInvalidInput = "CHAT_INVALID_INPUT"
	// ChatErrorCodeDisplayNotAuthorized — permit signature, binding, window, or
	// group-handle failure. One code for all of them: which check refused is not
	// something an unauthorized caller gets to learn.
	ChatErrorCodeDisplayNotAuthorized = "CHAT_DISPLAY_NOT_AUTHORIZED"
	// ChatErrorCodeDecryptFailed — a GCM tag / UTF-8 / AAD failure on any
	// message in the batch. The whole batch is refused with no partial output.
	ChatErrorCodeDecryptFailed = "CHAT_DECRYPT_FAILED"
)

// Wire-shape constants of the chat contract. These are the numbers the server,
// the Extension, and the Keeper agree on byte for byte (contract §4 / §5).
const (
	// ChatAADDomain / ChatAADVersion — the first two slots of the AAD the Keeper
	// builds for itself: `dragpass.chat|1|<org>|<conversation>|<dek_version>`.
	ChatAADDomain  = "dragpass.chat"
	ChatAADVersion = 1

	// ChatReadPermitDomain / ChatReadPermitCanonicalVersion — the first two
	// slots of the 9-item conversation-read-permit canonical.
	ChatReadPermitDomain           = "dragpass.chat.read"
	ChatReadPermitCanonicalVersion = 1

	// ChatReadPermitTTLSeconds — the server fixes
	// `expires_at = issued_at + 300`, and the Keeper requires exactly that
	// difference. A wider window is not a permit this contract issued; a
	// narrower one is not one the server signs.
	ChatReadPermitTTLSeconds = 300

	// ConversationDecryptMaxRequestBytes — 2 MiB. A batch of up to 200 messages
	// of ~8 KiB ciphertext each plus fixed context fits well under this; it
	// exists so a malformed or hostile payload is refused by length before it is
	// parsed.
	ConversationDecryptMaxRequestBytes = 2 * 1024 * 1024

	// ConversationDecryptMaxMessages — the batch cap. A larger batch is refused
	// rather than opened.
	ConversationDecryptMaxMessages = 200

	// ConversationIVBytes / ConversationCiphertextMinBytes /
	// ConversationCiphertextMaxBytes — `ciphertext_b64` carries
	// ciphertext ‖ GCM tag, so its floor is a 1-byte message plus the 16-byte
	// tag and its ceiling matches the server's VARBINARY(8208) column.
	ConversationIVBytes            = 12
	ConversationCiphertextMinBytes = 17
	ConversationCiphertextMaxBytes = 8208
)

// ConversationReadPermit is the server-signed authorization to read one
// conversation at one dek_version for a TTL window. The signature covers every
// field below except itself, in the canonical order §4 fixes.
//
// None of these fields is secret: they are the conversation context the caller
// already supplied plus the account the server bound. What the permit adds is
// the server's statement that this account may open this conversation now.
type ConversationReadPermit struct {
	AccountID        string `json:"account_id"` // from the user JWT, never from the request
	OrgID            string `json:"org_id"`
	ConversationID   string `json:"conversation_id"`
	DekVersion       int    `json:"dek_version"`
	IssuedAt         int64  `json:"issued_at"`
	ExpiresAt        int64  `json:"expires_at"` // issued_at + 300
	ServerKeyVersion uint   `json:"server_key_version"`
	Signature        string `json:"signature"` // Base64, RSA-PSS SHA-256 over the canonical
}

func (p ConversationReadPermit) Validate() error {
	if err := requireMessageUUID(p.AccountID, "permit.account_id"); err != nil {
		return err
	}
	if err := requireMessageUUID(p.OrgID, "permit.org_id"); err != nil {
		return err
	}
	if err := requireMessageUUID(p.ConversationID, "permit.conversation_id"); err != nil {
		return err
	}
	if err := requireMessageDekVersion(p.DekVersion, "permit.dek_version"); err != nil {
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

// ConversationDecryptMessage is one sealed chat message: the public IV and the
// ciphertext ‖ GCM tag. The Keeper opens it under the conversation DEK behind
// the group handle with an AAD it builds itself.
type ConversationDecryptMessage struct {
	IVB64         string `json:"iv_b64"`         // 12B IV, public material
	CiphertextB64 string `json:"ciphertext_b64"` // ciphertext ‖ GCM tag, public material
}

// ConversationDecryptBatchForAppDisplayRequest opens a page of one
// conversation's messages for browser display: the conversation context, the
// permit, and the batch.
type ConversationDecryptBatchForAppDisplayRequest struct {
	GroupHandle    string                       `json:"group_handle"`
	Permit         ConversationReadPermit       `json:"permit"`
	OrgID          string                       `json:"org_id"`
	ConversationID string                       `json:"conversation_id"`
	DekVersion     int                          `json:"dek_version"`
	Messages       []ConversationDecryptMessage `json:"messages"`
}

func (r ConversationDecryptBatchForAppDisplayRequest) Validate() error {
	if err := requireHandle(r.GroupHandle, "group_handle"); err != nil {
		return err
	}
	if err := r.Permit.Validate(); err != nil {
		return err
	}
	if err := requireMessageUUID(r.OrgID, "org_id"); err != nil {
		return err
	}
	if err := requireMessageUUID(r.ConversationID, "conversation_id"); err != nil {
		return err
	}
	if err := requireMessageDekVersion(r.DekVersion, "dek_version"); err != nil {
		return err
	}
	if len(r.Messages) > ConversationDecryptMaxMessages {
		return newValidationError("messages", "must carry at most "+
			strconv.Itoa(ConversationDecryptMaxMessages)+" entries")
	}
	for i := range r.Messages {
		field := "messages[" + strconv.Itoa(i) + "]"
		if err := requireMessageBase64Len(
			r.Messages[i].IVB64, field+".iv_b64", ConversationIVBytes, ConversationIVBytes,
		); err != nil {
			return err
		}
		if err := requireMessageBase64Len(
			r.Messages[i].CiphertextB64, field+".ciphertext_b64",
			ConversationCiphertextMinBytes, ConversationCiphertextMaxBytes,
		); err != nil {
			return err
		}
	}
	return nil
}

// ConversationDecryptBatchForAppDisplayResponseData carries the decrypted
// messages, parallel to request.messages.
//
// PlaintextB64 is the second TestNoRawSecretInResponseTypes carve-out (the
// first is 0.0.29's GroupDecryptWithAadForAppDisplayResponseData.plaintext_b64).
// The exception is approved for this response type alone; see the carve-out
// comment in no_raw_secret_response_test.go, dragpass-control-plane
// docs/exec-plans/active/dragpass-chat-1to1-implementation.md §5, and
// threat-model §4.10.
type ConversationDecryptBatchForAppDisplayResponseData struct {
	PlaintextB64 []string `json:"plaintext_b64"` // secret in RESPONSE — the approved chat carve-out; never logged
}

// ChatAADCanonical builds the additional authenticated data the chat messages
// were sealed under. The Keeper calls this with fields it validated itself; no
// part of it is taken from a caller-supplied canonical string.
//
// Pure function on purpose: CC1 (TypeScript) builds the same bytes on the
// encrypt side, and a golden-vector test on fixed inputs is what keeps the two
// honest.
func ChatAADCanonical(orgID, conversationID string, dekVersion int) string {
	return strings.Join([]string{
		ChatAADDomain,
		strconv.Itoa(ChatAADVersion),
		orgID,
		conversationID,
		strconv.Itoa(dekVersion),
	}, "|")
}

// ConversationReadPermitCanonical builds the 9-item string the server signs and
// the Keeper verifies. No trailing newline; the schema slot is always 1.
//
// Pure function on purpose, for the same reason as ChatAADCanonical: ariadne's
// signer (CC2) has to produce these bytes exactly.
func ConversationReadPermitCanonical(p ConversationReadPermit) string {
	return strings.Join([]string{
		ChatReadPermitDomain,
		strconv.Itoa(ChatReadPermitCanonicalVersion),
		p.AccountID,
		p.OrgID,
		p.ConversationID,
		strconv.Itoa(p.DekVersion),
		strconv.FormatInt(p.IssuedAt, 10),
		strconv.FormatInt(p.ExpiresAt, 10),
		strconv.FormatUint(uint64(p.ServerKeyVersion), 10),
	}, "|")
}
