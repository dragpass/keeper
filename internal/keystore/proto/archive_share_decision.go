package proto

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"math"
	"strconv"
	"strings"
)

const ArchiveShareDecisionTTLSeconds = 10

// ArchiveShareDecision is separate from Group DEK authority. The request
// digest commits the exact share envelope and recovery-session public key.
type ArchiveShareDecision struct {
	Challenge            string `json:"challenge"`
	AccountID            string `json:"account_id"`
	DeviceID             string `json:"device_id"`
	TokenID              string `json:"token_id"`
	SessionIssuedAtNanos int64  `json:"session_issued_at_nanos,string"`
	OrgID                string `json:"org_id"`
	RecoverySessionID    string `json:"recovery_session_id"`
	QuorumID             string `json:"quorum_id"`
	RequestDigest        string `json:"request_digest"`
	IssuedAt             int64  `json:"issued_at"`
	ExpiresAt            int64  `json:"expires_at"`
	ServerKeyVersion     uint   `json:"server_key_version"`
	Signature            string `json:"signature"`
}

func archiveShareCanonical(domain string, fields ...string) string {
	var b strings.Builder
	b.WriteString(domain)
	for _, field := range fields {
		b.WriteByte('|')
		b.WriteString(strconv.Itoa(len(field)))
		b.WriteByte(':')
		b.WriteString(field)
	}
	return b.String()
}

func ArchiveShareDecisionCanonical(d ArchiveShareDecision) string {
	return archiveShareCanonical("dragpass.archive.share.rewrap|1", d.Challenge, d.AccountID, d.DeviceID, d.TokenID,
		strconv.FormatInt(d.SessionIssuedAtNanos, 10), d.OrgID, d.RecoverySessionID, d.QuorumID, d.RequestDigest,
		strconv.FormatInt(d.IssuedAt, 10), strconv.FormatInt(d.ExpiresAt, 10), strconv.FormatUint(uint64(d.ServerKeyVersion), 10))
}

func (d ArchiveShareDecision) Validate() error {
	b, err := base64.RawURLEncoding.DecodeString(d.Challenge)
	if err != nil || len(b) != 32 || base64.RawURLEncoding.EncodeToString(b) != d.Challenge {
		return newValidationError("decision.challenge", "invalid challenge")
	}
	for _, id := range []string{d.AccountID, d.DeviceID, d.TokenID, d.OrgID, d.RecoverySessionID, d.QuorumID} {
		if err := requireMessageUUID(id, "decision.identity"); err != nil {
			return err
		}
	}
	if err := requireMessageDigest(d.RequestDigest, "decision.request_digest"); err != nil {
		return err
	}
	if d.SessionIssuedAtNanos <= 0 || d.IssuedAt <= 0 || d.ExpiresAt <= d.IssuedAt || d.ExpiresAt-d.IssuedAt != ArchiveShareDecisionTTLSeconds || d.ServerKeyVersion == 0 || d.ServerKeyVersion > math.MaxUint32 {
		return newValidationError("decision", "invalid validity or version")
	}
	if b, err := base64.StdEncoding.DecodeString(d.Signature); err != nil || len(b) == 0 {
		return newValidationError("decision.signature", "invalid signature")
	}
	return nil
}

func ArchiveShareRequestDigest(r ArchiveShareRewrapRequest) (string, error) {
	if err := r.Validate(); err != nil {
		return "", err
	}
	for _, id := range []string{r.AccountID, r.OrgID, r.RecoverySessionID} {
		if err := requireMessageUUID(id, "request.identity"); err != nil {
			return "", err
		}
	}
	digest := sha256.Sum256([]byte(archiveShareCanonical("dragpass.archive.share.request|1", r.AccountID, r.OrgID, r.RecoverySessionID, r.WrappedKey, r.Ciphertext, r.SessionPublicKey)))
	return hex.EncodeToString(digest[:]), nil
}

type ArchiveSharePrepareRequest struct {
	Request              ArchiveShareRewrapRequest `json:"request"`
	TokenID              string                    `json:"token_id"`
	SessionIssuedAtNanos int64                     `json:"session_issued_at_nanos,string"`
}

func (r ArchiveSharePrepareRequest) Validate() error {
	if _, err := ArchiveShareRequestDigest(r.Request); err != nil {
		return err
	}
	if err := requireMessageUUID(r.TokenID, "token_id"); err != nil {
		return err
	}
	if r.SessionIssuedAtNanos <= 0 {
		return newValidationError("session_issued_at_nanos", "must be positive")
	}
	return nil
}

type ArchiveSharePrepareResponseData struct {
	Challenge     string `json:"challenge"`
	RequestDigest string `json:"request_digest"`
}
