// message_display.go — payload models for the Secure Message Overlay display
// path (message_display_prepare, group_decrypt_with_aad_for_app_display).
//
// The two requests share the same nine structured fields — the message context
// the Keeper needs to rebuild the AAD by itself — and the display request adds
// the server-signed permit. There is deliberately no aad_b64, no domain, and no
// canonical field: the caller describes *which* message it is, never *how* it
// is bound. See actions_message.go for the security model and
// dragpass-control-plane
// docs/exec-plans/active/secure-message-overlay-implementation.md §1 / §3 for
// the contract these types implement.
//
// Validate() here is structural only — formats, ranges, and the fixed schema
// version. Everything that needs state (the challenge map, the signature, the
// permit window, the token expiry) is the handler's job and is checked there
// regardless of what Validate accepted.

package proto

import (
	"encoding/base64"
	"math"
	"strconv"
	"strings"
)

// Domain error codes for the message paths. Unlike the coarse ErrorCode
// taxonomy in errs/, these name the specific failure a message surface has to
// react to, and they are shared verbatim with the server and the Extension
// (implementation contract §4). They travel in the existing envelope's
// `error_code` field.
const (
	// MessageErrorCodeInvalidInput — malformed syntax, wrong size, unknown or
	// duplicate or missing field.
	MessageErrorCodeInvalidInput = "MESSAGE_INVALID_INPUT"
	// MessageErrorCodeDisplayBusy — the process-local challenge map is full.
	MessageErrorCodeDisplayBusy = "MESSAGE_DISPLAY_BUSY"
	// MessageErrorCodeDisplayNotAuthorized — signature, binding, challenge, or
	// permit-window failure. Deliberately one code for all four: which check
	// refused is not something an unauthorized caller gets to learn.
	MessageErrorCodeDisplayNotAuthorized = "MESSAGE_DISPLAY_NOT_AUTHORIZED"
	// MessageErrorCodeDecryptFailed — GCM tag or UTF-8 failure.
	MessageErrorCodeDecryptFailed = "MESSAGE_DECRYPT_FAILED"
	// MessageErrorCodeExpired — the message token's own expiry has passed.
	MessageErrorCodeExpired = "MESSAGE_EXPIRED"
)

// Wire-shape constants of the message contract. These are the numbers the
// server, the Extension, and the Keeper have to agree on byte for byte.
const (
	// MessageSchemaVersion — the `M=1` slot. The only accepted value; a token
	// claiming any other schema is refused rather than guessed at.
	MessageSchemaVersion = 1

	// MessageAADDomain / MessageAADVersion — the first two slots of the AAD the
	// Keeper builds for itself.
	MessageAADDomain  = "dragpass.message"
	MessageAADVersion = 1

	// MessageDisplayPermitDomain / MessageDisplayPermitCanonicalVersion — the
	// first two slots of the 14-item permit canonical.
	MessageDisplayPermitDomain           = "dragpass.message.display"
	MessageDisplayPermitCanonicalVersion = 1

	// MessageDisplayPermitTTLSeconds — the server fixes
	// `expires_at = issued_at + 30`, and the Keeper requires exactly that
	// difference. A wider window is not a permit this Keeper issued a challenge
	// for; a narrower one is not one the server signs.
	MessageDisplayPermitTTLSeconds = 30

	// MessageDisplayChallengeBytes / MessageDisplayChallengeChars — 32 CSPRNG
	// bytes, Base64URL with no padding, so exactly 43 characters.
	MessageDisplayChallengeBytes = 32
	MessageDisplayChallengeChars = 43

	// MessageDisplayMaxRequestBytes — 16 KiB. Both message actions carry at most
	// a 528-byte body plus fixed-width context, so this is roomy; it exists so a
	// malformed or hostile payload is refused by length before it is parsed.
	MessageDisplayMaxRequestBytes = 16 * 1024

	// MessageIVBytes / MessageCiphertextMinBytes / MessageCiphertextMaxBytes —
	// `ciphertext_b64` carries ciphertext ‖ GCM tag, so its floor is a 1-byte
	// message plus the 16-byte tag and its ceiling is 512 + 16.
	MessageIVBytes            = 12
	MessageCiphertextMinBytes = 17
	MessageCiphertextMaxBytes = 528

	// MessagePlaintextMinBytes / MessagePlaintextMaxBytes — enforced after the
	// open, on the decrypted bytes. An empty or oversized plaintext is a decrypt
	// failure, not a truncation opportunity.
	MessagePlaintextMinBytes = 1
	MessagePlaintextMaxBytes = 512

	// MessagePayloadDigestChars — lowercase hex of SHA-256.
	MessagePayloadDigestChars = 64

	// messageAuditTableAbsentSlot — what the canonical writes where an audit
	// table id would go when the message is not an audit message. A UUID can
	// never equal it, so the slot stays unambiguous.
	messageAuditTableAbsentSlot = "-"

	// messageMaxDekVersion — int32 ceiling, matching the server column.
	messageMaxDekVersion = 2147483647
	// messageMaxUnixSeconds — 11 decimal digits, the cap the contract puts on
	// the expiry slot.
	messageMaxUnixSeconds = 99999999999
	// messageMaxSafeInteger — permit timestamps cross a JS boundary, so they
	// stay inside the range JS can represent exactly.
	messageMaxSafeInteger = 9007199254740991
)

// MessageDisplayPrepareRequest is the prepare action's whole request: the nine
// structured fields that describe one message.
//
// The display request repeats the same nine rather than embedding them. The
// strict decoder and the no-raw-secret guards both read these structs field by
// field, and an embedded struct would only hide what crosses the boundary.
type MessageDisplayPrepareRequest struct {
	GroupHandle          string `json:"group_handle"`
	OrgID                string `json:"org_id"`
	GroupID              string `json:"group_id"`
	DekVersion           int    `json:"dek_version"`
	MessageSchemaVersion int    `json:"message_schema_version"`
	TokenExpiresAt       int64  `json:"token_expires_at"`
	// AuditTableID is the message's audit table for an audit-mode org and null
	// otherwise. The key is required either way — a missing key is refused
	// rather than read as null, so a dropped field cannot quietly turn an audit
	// message into a normal one.
	AuditTableID  *string `json:"audit_table_id"`
	IVB64         string  `json:"iv_b64"`         // 12B IV, public material
	CiphertextB64 string  `json:"ciphertext_b64"` // ciphertext ‖ GCM tag, public material
}

func (r MessageDisplayPrepareRequest) Validate() error {
	return validateMessageDisplayInput(
		r.GroupHandle, r.OrgID, r.GroupID, r.DekVersion, r.MessageSchemaVersion,
		r.TokenExpiresAt, r.AuditTableID, r.IVB64, r.CiphertextB64,
	)
}

// MessageDisplayPrepareResponseData carries the minted challenge and nothing
// else. The Extension hands it to the server to have a permit signed over it.
type MessageDisplayPrepareResponseData struct {
	Challenge string `json:"challenge"`
}

// MessageDisplayPermit is the server-signed authorization for one reveal of one
// message by one account. The signature covers every field below except itself,
// in the canonical order the implementation contract §3 fixes.
//
// None of these fields is secret: the challenge is a one-shot nonce this Keeper
// minted, the digest is over ciphertext, and the rest is context the caller
// already supplied. What the permit adds is the server's statement that this
// account may open this message right now.
type MessageDisplayPermit struct {
	Challenge            string  `json:"challenge"`
	GroupID              string  `json:"group_id"`
	DekVersion           int     `json:"dek_version"`
	MessageSchemaVersion int     `json:"message_schema_version"`
	TokenExpiresAt       int64   `json:"token_expires_at"`
	AuditTableID         *string `json:"audit_table_id"`
	PayloadSHA256        string  `json:"payload_sha256"` // lowercase hex of SHA256(IV ‖ ciphertext ‖ tag)
	AccountID            string  `json:"account_id"`     // from the user JWT, never from the request
	OrgID                string  `json:"org_id"`         // from the route, never from the request
	IssuedAt             int64   `json:"issued_at"`
	ExpiresAt            int64   `json:"expires_at"`
	ServerKeyVersion     uint    `json:"server_key_version"`
	Signature            string  `json:"signature"` // Base64, RSA-PSS SHA-256 over the canonical
}

func (p MessageDisplayPermit) Validate() error {
	if err := requireMessageChallenge(p.Challenge, "permit.challenge"); err != nil {
		return err
	}
	if err := requireMessageUUID(p.AccountID, "permit.account_id"); err != nil {
		return err
	}
	if err := requireMessageUUID(p.OrgID, "permit.org_id"); err != nil {
		return err
	}
	if err := requireMessageUUID(p.GroupID, "permit.group_id"); err != nil {
		return err
	}
	if err := requireMessageDekVersion(p.DekVersion, "permit.dek_version"); err != nil {
		return err
	}
	if err := requireMessageSchemaVersion(p.MessageSchemaVersion, "permit.message_schema_version"); err != nil {
		return err
	}
	if err := requireMessageExpiry(p.TokenExpiresAt, "permit.token_expires_at"); err != nil {
		return err
	}
	if err := requireMessageAuditTableID(p.AuditTableID, "permit.audit_table_id"); err != nil {
		return err
	}
	if err := requireMessageDigest(p.PayloadSHA256, "permit.payload_sha256"); err != nil {
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

// GroupDecryptWithAadForAppDisplayRequest is the display action's request: the
// same nine context fields as prepare, plus the permit.
//
// The spelling of the type name (Aad, not AAD) is the contract's, not Go's:
// the approved carve-out in TestNoRawSecretInResponseTypes names
// `GroupDecryptWithAadForAppDisplayResponseData.plaintext_b64` literally, and
// the exception has to be findable by that exact name.
type GroupDecryptWithAadForAppDisplayRequest struct {
	GroupHandle          string               `json:"group_handle"`
	OrgID                string               `json:"org_id"`
	GroupID              string               `json:"group_id"`
	DekVersion           int                  `json:"dek_version"`
	MessageSchemaVersion int                  `json:"message_schema_version"`
	TokenExpiresAt       int64                `json:"token_expires_at"`
	AuditTableID         *string              `json:"audit_table_id"`
	IVB64                string               `json:"iv_b64"`
	CiphertextB64        string               `json:"ciphertext_b64"`
	Permit               MessageDisplayPermit `json:"permit"`
}

func (r GroupDecryptWithAadForAppDisplayRequest) Validate() error {
	if err := validateMessageDisplayInput(
		r.GroupHandle, r.OrgID, r.GroupID, r.DekVersion, r.MessageSchemaVersion,
		r.TokenExpiresAt, r.AuditTableID, r.IVB64, r.CiphertextB64,
	); err != nil {
		return err
	}
	return r.Permit.Validate()
}

// GroupDecryptWithAadForAppDisplayResponseData carries the decrypted message.
//
// This single field is the protocol's only raw-secret response and the first
// TestNoRawSecretInResponseTypes carve-out since 0.0.11. The exception is
// approved for this response type alone; the rationale, the exposure table, and
// the invariants it must not widen live in dragpass-control-plane
// docs/security/secure-message-overlay-proposed-boundary.md.
type GroupDecryptWithAadForAppDisplayResponseData struct {
	PlaintextB64 string `json:"plaintext_b64"` // secret in RESPONSE — the approved display carve-out; never logged
}

// MessageAADCanonical builds the additional authenticated data the message was
// sealed under. The Keeper calls this with fields it has validated itself; no
// part of it is taken from a caller-supplied canonical string.
//
// Pure function on purpose: D1 (TypeScript) and D2 (ariadne) build the same
// bytes, and a golden-vector test on fixed inputs is what keeps the three
// honest.
func MessageAADCanonical(orgID, groupID string, dekVersion, schemaVersion int, tokenExpiresAt int64) string {
	return strings.Join([]string{
		MessageAADDomain,
		strconv.Itoa(schemaVersion),
		orgID,
		groupID,
		strconv.Itoa(dekVersion),
		strconv.FormatInt(tokenExpiresAt, 10),
	}, "|")
}

// MessageDisplayPermitCanonical builds the 14-item string the server signs and
// the Keeper verifies. No trailing newline; the schema slot is always the
// message schema version; an absent audit table writes "-".
//
// Pure function on purpose, for the same reason as MessageAADCanonical:
// ariadne's signer has to produce these bytes exactly.
func MessageDisplayPermitCanonical(p MessageDisplayPermit) string {
	return strings.Join([]string{
		MessageDisplayPermitDomain,
		strconv.Itoa(MessageDisplayPermitCanonicalVersion),
		p.Challenge,
		p.AccountID,
		p.OrgID,
		p.GroupID,
		strconv.Itoa(p.DekVersion),
		strconv.Itoa(p.MessageSchemaVersion),
		strconv.FormatInt(p.TokenExpiresAt, 10),
		MessageAuditTableSlot(p.AuditTableID),
		p.PayloadSHA256,
		strconv.FormatInt(p.IssuedAt, 10),
		strconv.FormatInt(p.ExpiresAt, 10),
		strconv.FormatUint(uint64(p.ServerKeyVersion), 10),
	}, "|")
}

// MessageAuditTableSlot renders the audit-table slot: the id, or "-" when the
// message is not an audit message. Comparing two slots is also how the handler
// compares two optional audit tables without dereferencing anything.
func MessageAuditTableSlot(id *string) string {
	if id == nil {
		return messageAuditTableAbsentSlot
	}
	return *id
}

// ────────────────────────────────────────────────────────────────────────
// Structural validation. Message fields get their own helpers rather than
// reusing requireBase64 and friends: the contract pins standard Base64,
// lowercase hyphenated UUIDs, and decimal integers with no sign, padding, or
// whitespace, and the lenient helpers accept more than that by design.
// ────────────────────────────────────────────────────────────────────────

func validateMessageDisplayInput(
	groupHandle, orgID, groupID string,
	dekVersion, schemaVersion int,
	tokenExpiresAt int64,
	auditTableID *string,
	ivB64, ciphertextB64 string,
) error {
	if err := requireHandle(groupHandle, "group_handle"); err != nil {
		return err
	}
	if err := requireMessageUUID(orgID, "org_id"); err != nil {
		return err
	}
	if err := requireMessageUUID(groupID, "group_id"); err != nil {
		return err
	}
	if err := requireMessageDekVersion(dekVersion, "dek_version"); err != nil {
		return err
	}
	if err := requireMessageSchemaVersion(schemaVersion, "message_schema_version"); err != nil {
		return err
	}
	if err := requireMessageExpiry(tokenExpiresAt, "token_expires_at"); err != nil {
		return err
	}
	if err := requireMessageAuditTableID(auditTableID, "audit_table_id"); err != nil {
		return err
	}
	if err := requireMessageBase64Len(ivB64, "iv_b64", MessageIVBytes, MessageIVBytes); err != nil {
		return err
	}
	return requireMessageBase64Len(
		ciphertextB64, "ciphertext_b64", MessageCiphertextMinBytes, MessageCiphertextMaxBytes,
	)
}

// requireMessageUUID enforces a lowercase hyphenated UUID and rejects the nil
// UUID. Version and variant nibbles are not pinned — the server owns id
// generation and a future v7 id must not become unreadable here.
func requireMessageUUID(value, field string) error {
	const uuidLen = 36
	if value == "" {
		return newValidationError(field, "must not be empty")
	}
	if len(value) != uuidLen {
		return newValidationError(field, "must be a 36-character lowercase UUID")
	}
	nilUUID := true
	for i := 0; i < uuidLen; i++ {
		c := value[i]
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return newValidationError(field, "must be a 36-character lowercase UUID")
			}
			continue
		}
		switch {
		case c >= '0' && c <= '9':
			if c != '0' {
				nilUUID = false
			}
		case c >= 'a' && c <= 'f':
			nilUUID = false
		default:
			return newValidationError(field, "must be a 36-character lowercase UUID")
		}
	}
	if nilUUID {
		return newValidationError(field, "must not be the nil UUID")
	}
	return nil
}

func requireMessageAuditTableID(value *string, field string) error {
	if value == nil {
		return nil
	}
	return requireMessageUUID(*value, field)
}

func requireMessageDekVersion(value int, field string) error {
	if value < 1 || value > messageMaxDekVersion {
		return newValidationError(field, "must be an integer in 1..2147483647")
	}
	return nil
}

// requireMessageSchemaVersion pins M=1. An unsupported schema fails closed
// rather than falling back to the current one.
func requireMessageSchemaVersion(value int, field string) error {
	if value != MessageSchemaVersion {
		return newValidationError(field, "must be "+strconv.Itoa(MessageSchemaVersion))
	}
	return nil
}

// requireMessageExpiry enforces the E slot: a positive Unix-seconds value of at
// most 11 digits. 0 and a missing value are not "no expiry" — the contract has
// no such thing.
func requireMessageExpiry(value int64, field string) error {
	if value < 1 || value > messageMaxUnixSeconds {
		return newValidationError(field, "must be a positive Unix-seconds value of at most 11 digits")
	}
	return nil
}

func requireMessageTimestamp(value int64, field string) error {
	if value < 1 || value > messageMaxSafeInteger {
		return newValidationError(field, "must be a positive safe integer")
	}
	return nil
}

// requireMessageChallenge enforces the shape the Keeper itself mints: 43
// Base64URL characters with no padding.
func requireMessageChallenge(value, field string) error {
	if len(value) != MessageDisplayChallengeChars {
		return newValidationError(
			field,
			"must be "+strconv.Itoa(MessageDisplayChallengeChars)+" Base64URL characters",
		)
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		isBase64URL := (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') || c == '-' || c == '_'
		if !isBase64URL {
			return newValidationError(field, "must be unpadded Base64URL")
		}
	}
	if _, err := base64.RawURLEncoding.DecodeString(value); err != nil {
		return newValidationError(field, "must be unpadded Base64URL")
	}
	return nil
}

// requireMessageDigest enforces 64 lowercase hex characters. Uppercase hex is
// rejected rather than folded: the digest is compared byte for byte against the
// one the Keeper computes, and accepting two spellings of the same value would
// make that comparison depend on who normalized first.
func requireMessageDigest(value, field string) error {
	if len(value) != MessagePayloadDigestChars {
		return newValidationError(
			field,
			"must be "+strconv.Itoa(MessagePayloadDigestChars)+" lowercase hex characters",
		)
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return newValidationError(field, "must be lowercase hex")
		}
	}
	return nil
}

// requireMessageBase64Len enforces standard padded Base64 decoding to a byte
// length inside [minLen, maxLen]. Standard only: requireBase64 falls back to
// URL-safe alphabets for legacy callers, and a message payload that decodes
// under two alphabets would hash differently depending on which one won.
func requireMessageBase64Len(value, field string, minLen, maxLen int) error {
	if value == "" {
		return newValidationError(field, "must not be empty")
	}
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return newValidationError(field, "must be valid standard Base64")
	}
	if len(decoded) < minLen || len(decoded) > maxLen {
		return newValidationError(field, "decoded length must be "+
			strconv.Itoa(minLen)+".."+strconv.Itoa(maxLen)+" bytes, got "+strconv.Itoa(len(decoded)))
	}
	return nil
}
