// change_compare.go — the server-signed comparison decision (lv83 H1).
//
// A tracked encrypt answers "same" or "changed" only under a decision the API
// signed for this account, device and session, this entry, the exact
// previous record and the current Group grant, bound to a one-use Keeper
// challenge (lv79 online decision pattern). Without one the verdict is
// "unknown": the token and the next record are still sealed. The API issues
// the decision only to a caller with the current Group display authority
// (PermDecrypt) and edit authority on the item, so a caller who gets a verdict
// could already decrypt the value. Contract: docs/protocol.md "Entry
// value-change tracking".

package proto

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"math"
	"strconv"
	"strings"
)

const (
	ActionGroupChangeComparePrepare = "group_change_compare_prepare"

	GroupChangeComparePrepareMaxRequestBytes = 16 * 1024

	// ChangeCompareDecisionTTLSeconds equals the display decision window.
	ChangeCompareDecisionTTLSeconds = CurrentGroupDisplayDecisionTTLSeconds

	changeCompareDecisionDomain  = "dragpass.drag.change-compare"
	changeCompareOperationDomain = "dragpass.drag.change-compare.op|1"
	changeRecordDigestDomain     = "dragpass.drag.change.record|1"
)

// ChangeRecordDigest is SHA-256 over the domain and the exact record bytes,
// version and sequence. ariadne computes the same digest from the record it
// stores.
func ChangeRecordDigest(iv, ciphertext []byte, dekVersion int, seq uint64) [32]byte {
	h := sha256.New()
	h.Write([]byte(changeRecordDigestDomain))
	for _, field := range [][]byte{iv, ciphertext} {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(field)))
		h.Write(n[:])
		h.Write(field)
	}
	var v [4]byte
	binary.BigEndian.PutUint32(v[:], uint32(dekVersion))
	h.Write(v[:])
	var s [8]byte
	binary.BigEndian.PutUint64(s[:], seq)
	h.Write(s[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// GroupChangeComparePrepareRequest names the Group handle a tracked encrypt
// will use, the entry and the exact previous record.
type GroupChangeComparePrepareRequest struct {
	GroupHandle    string       `json:"group_handle"`
	OrgID          string       `json:"org_id"`
	GroupID        string       `json:"group_id"`
	DekVersion     int          `json:"dek_version"`
	EntryID        string       `json:"entry_id"`
	PreviousRecord ChangeRecord `json:"previous_record"`
	TokenID        string       `json:"token_id"`
	// The JWT nanosecond value exceeds JavaScript's exact integer range.
	SessionIssuedAtNanos string `json:"session_issued_at_nanos"`
}

func (r GroupChangeComparePrepareRequest) Validate() error {
	if _, err := requireBase64Len(r.GroupHandle, "group_handle", 32); err != nil {
		return err
	}
	for _, item := range []struct{ value, field string }{
		{r.OrgID, "org_id"}, {r.GroupID, "group_id"}, {r.EntryID, "entry_id"}, {r.TokenID, "token_id"},
	} {
		if err := requireMessageUUID(item.value, item.field); err != nil {
			return err
		}
	}
	if err := requireMessageDekVersion(r.DekVersion, "dek_version"); err != nil {
		return err
	}
	if err := r.PreviousRecord.validate(); err != nil {
		return err
	}
	if _, err := requireBase64(r.PreviousRecord.IVB64, "previous_record.iv_b64"); err != nil {
		return err
	}
	if _, err := requireBase64(r.PreviousRecord.CiphertextB64, "previous_record.ciphertext_b64"); err != nil {
		return err
	}
	nanos, err := strconv.ParseInt(r.SessionIssuedAtNanos, 10, 64)
	if err != nil || nanos <= 0 || strconv.FormatInt(nanos, 10) != r.SessionIssuedAtNanos {
		return newValidationError("session_issued_at_nanos", "must be a canonical positive int64 decimal string")
	}
	return nil
}

// GroupChangeComparePrepareResponseData — public commitments only.
type GroupChangeComparePrepareResponseData struct {
	Challenge       string `json:"challenge"`
	GroupID         string `json:"group_id"`
	DekVersion      int    `json:"dek_version"`
	GrantDigest     string `json:"grant_digest"`
	RecordDigest    string `json:"record_digest"`
	OperationDigest string `json:"operation_digest"`
}

// ChangeCompareOperationDigest commits to the challenge, the handle, the entry
// and the record digest.
func ChangeCompareOperationDigest(challenge [32]byte, handle []byte, entryID string, recordDigest [32]byte) [32]byte {
	h := sha256.New()
	h.Write([]byte(changeCompareOperationDomain))
	for _, field := range [][]byte{challenge[:], handle, []byte(entryID), recordDigest[:]} {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(field)))
		h.Write(n[:])
		h.Write(field)
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// ChangeCompareDecision is the API-signed statement for one comparison.
type ChangeCompareDecision struct {
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
	RecordDigest         string `json:"record_digest"`
	OperationDigest      string `json:"operation_digest"`
	IssuedAt             int64  `json:"issued_at"`
	ExpiresAt            int64  `json:"expires_at"`
	ServerKeyVersion     uint   `json:"server_key_version"`
	Signature            string `json:"signature"`
}

// ChangeCompareDecisionCanonical matches ariadne's v1 signing bytes.
func ChangeCompareDecisionCanonical(d ChangeCompareDecision) string {
	return strings.Join([]string{
		changeCompareDecisionDomain, "1", d.Challenge, d.AccountID, d.DeviceID,
		d.TokenID, strconv.FormatInt(d.SessionIssuedAtNanos, 10), d.OrgID, d.GroupID,
		strconv.Itoa(d.DekVersion), d.GrantDigest, d.EntryID, d.RecordDigest,
		d.OperationDigest, strconv.FormatInt(d.IssuedAt, 10),
		strconv.FormatInt(d.ExpiresAt, 10), strconv.FormatUint(uint64(d.ServerKeyVersion), 10),
	}, "|")
}

// Validate checks the statement's shape before signature verification.
func (d ChangeCompareDecision) Validate() error {
	challenge, err := base64.RawURLEncoding.DecodeString(d.Challenge)
	if err != nil || len(challenge) != 32 || base64.RawURLEncoding.EncodeToString(challenge) != d.Challenge {
		return newValidationError("compare_decision.challenge", "must be canonical 32-byte Base64URL")
	}
	for _, item := range []struct{ value, field string }{
		{d.AccountID, "compare_decision.account_id"},
		{d.DeviceID, "compare_decision.device_id"},
		{d.TokenID, "compare_decision.token_id"},
		{d.OrgID, "compare_decision.org_id"},
		{d.GroupID, "compare_decision.group_id"},
		{d.EntryID, "compare_decision.entry_id"},
	} {
		if err := requireMessageUUID(item.value, item.field); err != nil {
			return err
		}
	}
	if d.SessionIssuedAtNanos <= 0 {
		return newValidationError("compare_decision.session_issued_at_nanos", "must be positive")
	}
	if err := requireMessageDekVersion(d.DekVersion, "compare_decision.dek_version"); err != nil {
		return err
	}
	for _, item := range []struct{ value, field string }{
		{d.GrantDigest, "compare_decision.grant_digest"},
		{d.RecordDigest, "compare_decision.record_digest"},
		{d.OperationDigest, "compare_decision.operation_digest"},
	} {
		if err := requireMessageDigest(item.value, item.field); err != nil {
			return err
		}
		if item.value == strings.Repeat("0", 64) {
			return newValidationError(item.field, "must not be zero")
		}
	}
	if err := requireMessageTimestamp(d.IssuedAt, "compare_decision.issued_at"); err != nil {
		return err
	}
	if err := requireMessageTimestamp(d.ExpiresAt, "compare_decision.expires_at"); err != nil {
		return err
	}
	if d.ExpiresAt-d.IssuedAt != ChangeCompareDecisionTTLSeconds {
		return newValidationError("compare_decision.expires_at", "invalid validity window")
	}
	if d.ServerKeyVersion < 1 || d.ServerKeyVersion > math.MaxUint32 {
		return newValidationError("compare_decision.server_key_version", "must be a positive uint32")
	}
	if _, err := base64.StdEncoding.DecodeString(d.Signature); err != nil || d.Signature == "" {
		return newValidationError("compare_decision.signature", "must be standard Base64")
	}
	return nil
}
