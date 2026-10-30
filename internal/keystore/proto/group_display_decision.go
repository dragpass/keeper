package proto

import (
	"encoding/base64"
	"math"
	"strconv"
	"strings"
)

const CurrentGroupDisplayDecisionTTLSeconds = 10

// CurrentGroupDisplayDecision is an API-signed statement for one Group display
// attempt. It is not authority until a Keeper challenge and local operation
// are matched and the server signature is verified.
type CurrentGroupDisplayDecision struct {
	Challenge            string `json:"challenge"`
	AccountID            string `json:"account_id"`
	DeviceID             string `json:"device_id"`
	TokenID              string `json:"token_id"`
	SessionIssuedAtNanos int64  `json:"session_issued_at_nanos"`
	GroupID              string `json:"group_id"`
	DekVersion           int    `json:"dek_version"`
	GrantDigest          string `json:"grant_digest"`
	OperationDigest      string `json:"operation_digest"`
	FrameKeyDigest       string `json:"frame_key_digest"`
	IssuedAt             int64  `json:"issued_at"`
	ExpiresAt            int64  `json:"expires_at"`
	ServerKeyVersion     uint   `json:"server_key_version"`
	Signature            string `json:"signature"`
}

// CurrentGroupDisplayDecisionCanonical matches Ariadne's v1 signing bytes.
func CurrentGroupDisplayDecisionCanonical(d CurrentGroupDisplayDecision) string {
	return strings.Join([]string{
		"dragpass.group.display", "1", d.Challenge, d.AccountID, d.DeviceID,
		d.TokenID, strconv.FormatInt(d.SessionIssuedAtNanos, 10), d.GroupID,
		strconv.Itoa(d.DekVersion), d.GrantDigest, d.OperationDigest,
		d.FrameKeyDigest, strconv.FormatInt(d.IssuedAt, 10),
		strconv.FormatInt(d.ExpiresAt, 10), strconv.FormatUint(uint64(d.ServerKeyVersion), 10),
	}, "|")
}

// Validate checks the signed statement's shape before signature verification.
// It does not authorize an operation or consume a Keeper challenge.
func (d CurrentGroupDisplayDecision) Validate() error {
	if err := requireMessageChallenge(d.Challenge, "decision.challenge"); err != nil {
		return err
	}
	challenge, _ := base64.RawURLEncoding.DecodeString(d.Challenge)
	if len(challenge) != 32 || base64.RawURLEncoding.EncodeToString(challenge) != d.Challenge {
		return newValidationError("decision.challenge", "must be canonical 32-byte Base64URL")
	}
	for _, item := range []struct{ value, field string }{
		{d.AccountID, "decision.account_id"},
		{d.DeviceID, "decision.device_id"},
		{d.TokenID, "decision.token_id"},
		{d.GroupID, "decision.group_id"},
	} {
		if err := requireMessageUUID(item.value, item.field); err != nil {
			return err
		}
	}
	if d.SessionIssuedAtNanos <= 0 {
		return newValidationError("decision.session_issued_at_nanos", "must be positive")
	}
	if err := requireMessageDekVersion(d.DekVersion, "decision.dek_version"); err != nil {
		return err
	}
	for _, item := range []struct{ value, field string }{
		{d.GrantDigest, "decision.grant_digest"},
		{d.OperationDigest, "decision.operation_digest"},
		{d.FrameKeyDigest, "decision.frame_key_digest"},
	} {
		if err := requireMessageDigest(item.value, item.field); err != nil {
			return err
		}
		if item.value == strings.Repeat("0", 64) {
			return newValidationError(item.field, "must not be zero")
		}
	}
	if err := requireMessageTimestamp(d.IssuedAt, "decision.issued_at"); err != nil {
		return err
	}
	if err := requireMessageTimestamp(d.ExpiresAt, "decision.expires_at"); err != nil {
		return err
	}
	if d.ExpiresAt-d.IssuedAt != CurrentGroupDisplayDecisionTTLSeconds {
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
