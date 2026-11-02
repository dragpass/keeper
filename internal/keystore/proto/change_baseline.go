// change_baseline.go — the Group change-baseline actions (lv83).
//
// A baseline is the first comparison record of a tracked entry, made from an
// existing token instead of a save. It follows the lv79 online decision
// pattern: prepare binds the exact token and entry to a one-use challenge, the
// API signs a short-lived decision for the current session, device, Group
// authority and item, and execute verifies that decision before opening the
// token. The response is a sealed record only. Contract: docs/protocol.md
// "Entry value-change tracking".

package proto

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"math"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	ActionGroupChangeBaselinePrepare = "group_change_baseline_prepare"
	ActionGroupChangeBaselineExecute = "group_change_baseline_execute"

	GroupChangeBaselinePrepareMaxRequestBytes = 16 * 1024
	GroupChangeBaselineExecuteMaxRequestBytes = 20 * 1024

	// ChangeBaselineDecisionTTLSeconds equals the display decision window so
	// the API's display horizons order it against revocations the same way.
	ChangeBaselineDecisionTTLSeconds = CurrentGroupDisplayDecisionTTLSeconds

	changeBaselineDecisionDomain  = "dragpass.drag.change-baseline"
	changeBaselineOperationDomain = "dragpass.drag.change-baseline.op|1"
)

// GroupChangeBaselinePrepareRequest names one existing bound token of one
// entry. The account and device come from Keeper, not from the caller.
type GroupChangeBaselinePrepareRequest struct {
	GroupHandle   string `json:"group_handle"`
	Token         string `json:"token"`
	OrgID         string `json:"org_id"`
	GroupID       string `json:"group_id"`
	DekVersion    int    `json:"dek_version"`
	TokenExpiry   string `json:"token_expiry,omitempty"`
	IVB64         string `json:"iv_b64"`
	CiphertextB64 string `json:"ciphertext_b64"`
	EntryID       string `json:"entry_id"`
	TokenID       string `json:"token_id"`
	// The JWT nanosecond value exceeds JavaScript's exact integer range.
	SessionIssuedAtNanos string `json:"session_issued_at_nanos"`
}

func (r GroupChangeBaselinePrepareRequest) Validate() error {
	if _, err := requireBase64Len(r.GroupHandle, "group_handle", 32); err != nil {
		return err
	}
	if len(r.Token) == 0 || len(r.Token) > 8192 || !utf8.ValidString(r.Token) {
		return newValidationError("token", "must be valid UTF-8 within 1..8192 bytes")
	}
	if _, err := requireBase64Len(r.IVB64, "iv_b64", 12); err != nil {
		return err
	}
	ciphertext, err := requireBase64(r.CiphertextB64, "ciphertext_b64")
	if err != nil {
		return err
	}
	if len(ciphertext) < 16 || len(ciphertext) > 8192 {
		return newValidationError("ciphertext_b64", "decoded length must be within 16..8192 bytes")
	}
	if err := requireMessageUUID(r.EntryID, "entry_id"); err != nil {
		return err
	}
	if err := requireMessageUUID(r.TokenID, "token_id"); err != nil {
		return err
	}
	if err := validateDisplayTokenScope(r.OrgID, r.GroupID, r.DekVersion, r.TokenExpiry); err != nil {
		return err
	}
	nanos, err := strconv.ParseInt(r.SessionIssuedAtNanos, 10, 64)
	if err != nil || nanos <= 0 || strconv.FormatInt(nanos, 10) != r.SessionIssuedAtNanos {
		return newValidationError("session_issued_at_nanos", "must be a canonical positive int64 decimal string")
	}
	return nil
}

// GroupChangeBaselinePrepareResponseData — public commitments only.
type GroupChangeBaselinePrepareResponseData struct {
	Challenge        string `json:"challenge"`
	GroupID          string `json:"group_id"`
	DekVersion       int    `json:"dek_version"`
	GrantDigest      string `json:"grant_digest"`
	OperationDigest  string `json:"operation_digest"`
	TokenFingerprint string `json:"token_fingerprint"`
}

// ChangeBaselineOperation is everything a baseline decision commits to on the
// Keeper side.
type ChangeBaselineOperation struct {
	Challenge   [32]byte
	GroupHandle [32]byte
	Token       []byte
	TokenAAD    []byte
	IV          [12]byte
	Ciphertext  []byte
	EntryID     string
}

// ChangeBaselineOperationDigest is SHA-256 over the domain and the
// length-prefixed fields, so no two operations share a digest.
func ChangeBaselineOperationDigest(op ChangeBaselineOperation) [32]byte {
	h := sha256.New()
	h.Write([]byte(changeBaselineOperationDomain))
	for _, field := range [][]byte{
		op.Challenge[:], op.GroupHandle[:], op.Token, op.TokenAAD, op.IV[:], op.Ciphertext, []byte(op.EntryID),
	} {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(field)))
		h.Write(n[:])
		h.Write(field)
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// ChangeBaselineDecision is the API-signed statement for one baseline. It is
// not authority until Keeper matches it to its own pending operation and
// verifies the signature.
type ChangeBaselineDecision struct {
	Challenge            string `json:"challenge"`
	AccountID            string `json:"account_id"`
	DeviceID             string `json:"device_id"`
	TokenID              string `json:"token_id"`
	SessionIssuedAtNanos int64  `json:"session_issued_at_nanos,string"`
	OrgID                string `json:"org_id"`
	GroupID              string `json:"group_id"`
	DekVersion           int    `json:"dek_version"`
	GrantDigest          string `json:"grant_digest"`
	EntryID              string `json:"entry_id"`
	TokenFingerprint     string `json:"token_fingerprint"`
	OperationDigest      string `json:"operation_digest"`
	IssuedAt             int64  `json:"issued_at"`
	ExpiresAt            int64  `json:"expires_at"`
	ServerKeyVersion     uint   `json:"server_key_version"`
	Signature            string `json:"signature"`
}

// ChangeBaselineDecisionCanonical matches ariadne's v1 signing bytes.
func ChangeBaselineDecisionCanonical(d ChangeBaselineDecision) string {
	return strings.Join([]string{
		changeBaselineDecisionDomain, "1", d.Challenge, d.AccountID, d.DeviceID,
		d.TokenID, strconv.FormatInt(d.SessionIssuedAtNanos, 10), d.OrgID, d.GroupID,
		strconv.Itoa(d.DekVersion), d.GrantDigest, d.EntryID, d.TokenFingerprint,
		d.OperationDigest, strconv.FormatInt(d.IssuedAt, 10),
		strconv.FormatInt(d.ExpiresAt, 10), strconv.FormatUint(uint64(d.ServerKeyVersion), 10),
	}, "|")
}

// Validate checks the statement's shape before signature verification.
func (d ChangeBaselineDecision) Validate() error {
	challenge, err := base64.RawURLEncoding.DecodeString(d.Challenge)
	if err != nil || len(challenge) != 32 || base64.RawURLEncoding.EncodeToString(challenge) != d.Challenge {
		return newValidationError("decision.challenge", "must be canonical 32-byte Base64URL")
	}
	for _, item := range []struct{ value, field string }{
		{d.AccountID, "decision.account_id"},
		{d.DeviceID, "decision.device_id"},
		{d.TokenID, "decision.token_id"},
		{d.OrgID, "decision.org_id"},
		{d.GroupID, "decision.group_id"},
		{d.EntryID, "decision.entry_id"},
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
		{d.TokenFingerprint, "decision.token_fingerprint"},
		{d.OperationDigest, "decision.operation_digest"},
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
	if d.ExpiresAt-d.IssuedAt != ChangeBaselineDecisionTTLSeconds {
		return newValidationError("decision.expires_at", "invalid validity window")
	}
	if d.ServerKeyVersion < 1 || d.ServerKeyVersion > math.MaxUint32 {
		return newValidationError("decision.server_key_version", "must be a positive uint32")
	}
	if _, err := base64.StdEncoding.DecodeString(d.Signature); err != nil || d.Signature == "" {
		return newValidationError("decision.signature", "must be standard Base64")
	}
	return nil
}

// GroupChangeBaselineExecuteRequest repeats the exact prepare request with the
// signed decision.
type GroupChangeBaselineExecuteRequest struct {
	Prepare  GroupChangeBaselinePrepareRequest `json:"prepare"`
	Decision ChangeBaselineDecision            `json:"decision"`
}

func (r GroupChangeBaselineExecuteRequest) Validate() error {
	if err := r.Prepare.Validate(); err != nil {
		return err
	}
	return r.Decision.Validate()
}

// GroupChangeBaselineExecuteResponseData — the sealed baseline record only.
type GroupChangeBaselineExecuteResponseData struct {
	ChangeVerdict string       `json:"change_verdict"`
	ChangeRecord  ChangeRecord `json:"change_record"`
}
