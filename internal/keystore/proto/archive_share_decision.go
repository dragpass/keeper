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
const ArchiveRequesterProofMaxBytes = 512 * 1024

// The sealed proof grows by one third in base64. Leave room for the signed decision and share.
const ArchiveShareRewrapMaxRequestBytes = 768 * 1024

type ArchiveRequesterProofEnvelope struct {
	WrappedKey string `json:"wrapped_key"`
	Ciphertext string `json:"ciphertext"`
}

// ArchiveRecoveryTarget is the target of the pending card selected in the paired App.
type ArchiveRecoveryTarget struct {
	RequesterAccountID string `json:"requester_account_id"`
	GroupID            string `json:"group_id"`
	DekVersion         int    `json:"dek_version"`
}

// ArchiveShareDecision is separate from Group DEK authority. The request
// digest commits the exact share envelope and recovery-session public key.
type ArchiveShareDecision struct {
	Purpose              string                         `json:"purpose"`
	SplitOperationID     string                         `json:"split_operation_id,omitempty"`
	RequesterProof       *ArchiveRequesterProofEnvelope `json:"requester_proof,omitempty"`
	Challenge            string                         `json:"challenge"`
	AccountID            string                         `json:"account_id"`
	DeviceID             string                         `json:"device_id"`
	TokenID              string                         `json:"token_id"`
	SessionIssuedAtNanos int64                          `json:"session_issued_at_nanos,string"`
	OrgID                string                         `json:"org_id"`
	RecoverySessionID    string                         `json:"recovery_session_id"`
	QuorumID             string                         `json:"quorum_id"`
	RequestDigest        string                         `json:"request_digest"`
	IssuedAt             int64                          `json:"issued_at"`
	ExpiresAt            int64                          `json:"expires_at"`
	ServerKeyVersion     uint                           `json:"server_key_version"`
	Signature            string                         `json:"signature"`
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
	proofDigest := ""
	if p := d.RequesterProof; p != nil {
		sum := sha256.Sum256([]byte(archiveShareCanonical("dragpass.archive.requester-proof|1", p.WrappedKey, p.Ciphertext)))
		proofDigest = hex.EncodeToString(sum[:])
	}
	return archiveShareCanonical("dragpass.archive.share.rewrap|2", d.Challenge, d.AccountID, d.DeviceID, d.TokenID,
		strconv.FormatInt(d.SessionIssuedAtNanos, 10), d.OrgID, d.RecoverySessionID, d.QuorumID, d.RequestDigest,
		strconv.FormatInt(d.IssuedAt, 10), strconv.FormatInt(d.ExpiresAt, 10), strconv.FormatUint(uint64(d.ServerKeyVersion), 10), d.Purpose, d.SplitOperationID, proofDigest)
}

func (d ArchiveShareDecision) Validate() error {
	switch d.Purpose {
	case "recovery":
		p := d.RequesterProof
		if d.SplitOperationID != "" || p == nil || p.WrappedKey == "" || len(p.WrappedKey) > 2048 || p.Ciphertext == "" || len(p.Ciphertext) > base64.StdEncoding.EncodedLen(ArchiveRequesterProofMaxBytes+28) {
			return newValidationError("requester_proof", "invalid recovery attachment")
		}
	case "reconfiguration":
		if d.RequesterProof != nil || requireMessageUUID(d.SplitOperationID, "split_operation_id") != nil {
			return newValidationError("decision", "invalid reconfiguration scope")
		}
	default:
		return newValidationError("decision.purpose", "unknown authorization purpose")
	}
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
	if t := r.RecoveryTarget; t != nil {
		if r.SplitOperationID != "" || requireMessageUUID(t.RequesterAccountID, "requester_account_id") != nil || requireMessageUUID(t.GroupID, "group_id") != nil || t.DekVersion < 1 {
			return "", newValidationError("recovery_target", "invalid recovery target")
		}
	} else if err := requireMessageUUID(r.SplitOperationID, "split_operation_id"); err != nil {
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
	RequesterPinFingerprint string  `json:"requester_pin_fingerprint,omitempty"`
	PreviousTreeSize        *uint64 `json:"previous_tree_size,omitempty"`
	Challenge               string  `json:"challenge"`
	RequestDigest           string  `json:"request_digest"`
}
