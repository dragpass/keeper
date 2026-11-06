package proto

import (
	"encoding/base64"
	"math"
	"strconv"
	"strings"
)

const GroupRewrapDecisionTTLSeconds = 10

// GroupRewrapDecision is a signed statement for one exact Keeper challenge.
// Its fields are not authority until Keeper verifies the signature and state.
type GroupRewrapDecision struct {
	Challenge            string `json:"challenge"`
	AccountID            string `json:"account_id"`
	DeviceID             string `json:"device_id"`
	TokenID              string `json:"token_id"`
	SessionIssuedAtNanos int64  `json:"session_issued_at_nanos,string"`
	Operation            string `json:"operation"`
	OrgID                string `json:"org_id"`
	GroupID              string `json:"group_id"`
	DEKVersion           int    `json:"dek_version"`
	SourceKind           string `json:"source_kind"`
	SourceGrantDigest    string `json:"source_grant_digest"`
	SourcePolicy         string `json:"source_policy"`
	OutputPolicy         string `json:"output_policy"`
	RequestDigest        string `json:"request_digest"`
	RecipientsDigest     string `json:"recipients_digest"`
	IssuedAt             int64  `json:"issued_at"`
	ExpiresAt            int64  `json:"expires_at"`
	ServerKeyVersion     uint   `json:"server_key_version"`
	Signature            string `json:"signature"`
}

// GroupRewrapDecisionCanonical must match Ariadne's signing bytes exactly.
// The caller validates every field before signing or accepting the decision.
func GroupRewrapDecisionCanonical(d GroupRewrapDecision) string {
	fields := []string{d.Challenge, d.AccountID, d.DeviceID,
		d.TokenID, strconv.FormatInt(d.SessionIssuedAtNanos, 10), d.Operation,
		d.OrgID, d.GroupID, strconv.Itoa(d.DEKVersion), d.SourceKind,
		d.SourceGrantDigest, d.SourcePolicy, d.OutputPolicy, d.RequestDigest,
		d.RecipientsDigest, strconv.FormatInt(d.IssuedAt, 10),
		strconv.FormatInt(d.ExpiresAt, 10), strconv.FormatUint(uint64(d.ServerKeyVersion), 10),
	}
	var canonical strings.Builder
	canonical.WriteString("dragpass.group.rewrap|1")
	for _, field := range fields {
		canonical.WriteByte('|')
		canonical.WriteString(strconv.Itoa(len(field)))
		canonical.WriteByte(':')
		canonical.WriteString(field)
	}
	return canonical.String()
}

// Validate checks the statement shape. It does not verify the signature,
// current server authority, or the Keeper challenge and local binding.
func (d GroupRewrapDecision) Validate() error {
	if err := requireMessageChallenge(d.Challenge, "decision.challenge"); err != nil {
		return err
	}
	challenge, err := base64.RawURLEncoding.DecodeString(d.Challenge)
	if err != nil || len(challenge) != 32 || base64.RawURLEncoding.EncodeToString(challenge) != d.Challenge {
		return newValidationError("decision.challenge", "must be canonical 32-byte Base64URL")
	}
	for _, item := range []struct{ value, field string }{
		{d.AccountID, "decision.account_id"}, {d.DeviceID, "decision.device_id"},
		{d.TokenID, "decision.token_id"}, {d.OrgID, "decision.org_id"},
		{d.GroupID, "decision.group_id"},
	} {
		if err := requireMessageUUID(item.value, item.field); err != nil {
			return err
		}
	}
	if d.SessionIssuedAtNanos <= 0 {
		return newValidationError("decision.session_issued_at_nanos", "must be positive")
	}
	if err := requireRewrapDecisionName(d.Operation, "decision.operation"); err != nil {
		return err
	}
	if err := requireMessageDekVersion(d.DEKVersion, "decision.dek_version"); err != nil {
		return err
	}
	if err := requireRewrapDecisionName(d.SourceKind, "decision.source_kind"); err != nil {
		return err
	}
	for _, item := range []struct{ value, field string }{
		{d.SourceGrantDigest, "decision.source_grant_digest"},
		{d.RequestDigest, "decision.request_digest"},
		{d.RecipientsDigest, "decision.recipients_digest"},
	} {
		if err := requireMessageDigest(item.value, item.field); err != nil {
			return err
		}
		if item.value == strings.Repeat("0", 64) {
			return newValidationError(item.field, "must not be zero")
		}
	}
	for _, item := range []struct{ value, field string }{
		{d.SourcePolicy, "decision.source_policy"},
		{d.OutputPolicy, "decision.output_policy"},
	} {
		if item.value != GrantPolicyLegacy && item.value != GrantPolicyAuditOnlyV1 && item.value != GrantPolicyDecryptOnlyV1 {
			return newValidationError(item.field, "unsupported grant policy")
		}
	}
	if err := requireMessageTimestamp(d.IssuedAt, "decision.issued_at"); err != nil {
		return err
	}
	if err := requireMessageTimestamp(d.ExpiresAt, "decision.expires_at"); err != nil {
		return err
	}
	if d.ExpiresAt-d.IssuedAt != GroupRewrapDecisionTTLSeconds {
		return newValidationError("decision.expires_at", "invalid validity window")
	}
	if d.ServerKeyVersion < 1 || d.ServerKeyVersion > math.MaxUint32 {
		return newValidationError("decision.server_key_version", "must be a positive uint32")
	}
	if d.Signature == "" {
		return newValidationError("decision.signature", "must not be empty")
	}
	if _, err := base64.StdEncoding.DecodeString(d.Signature); err != nil {
		return newValidationError("decision.signature", "must be standard Base64")
	}
	return nil
}

func requireRewrapDecisionName(value, field string) error {
	if len(value) == 0 || len(value) > 64 {
		return newValidationError(field, "must be a short ASCII name")
	}
	for i := range len(value) {
		c := value[i]
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_') {
			return newValidationError(field, "must be a short ASCII name")
		}
	}
	return nil
}
