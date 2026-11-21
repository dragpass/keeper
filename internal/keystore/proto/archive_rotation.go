package proto

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strconv"
)

type RotationShare struct {
	AccountID  string `json:"account_id"`
	Index      int    `json:"share_index"`
	WrappedKey string `json:"wrapped_key"`
	Ciphertext string `json:"ciphertext"`
}

type RotationGrant struct {
	ID      string `json:"grant_id"`
	GroupID string `json:"group_id"`
	Version int    `json:"dek_version"`
	Wrapped string `json:"wrapped_old_group_dek"`
	Policy  string `json:"grant_policy"`
}

func (g RotationGrant) Context(org string) *GrantContext {
	return &GrantContext{Policy: g.Policy, OrgID: org, GroupID: g.GroupID, DekVersion: g.Version}
}

type ArchiveRotationRequest struct {
	OrgID        string          `json:"org_id"`
	OperationID  string          `json:"operation_id"`
	SessionID    string          `json:"session_id"`
	ConfigDigest string          `json:"config_digest"`
	Shares       []RotationShare `json:"shares"`
	Grants       []RotationGrant `json:"grants"`
}
type RotationDecision struct {
	Challenge     string `json:"challenge"`
	AccountID     string `json:"account_id"`
	DeviceID      string `json:"device_id"`
	TokenID       string `json:"token_id"`
	SessionStart  int64  `json:"session_issued_at_nanos,string"`
	OrgID         string `json:"org_id"`
	OperationID   string `json:"operation_id"`
	SessionID     string `json:"session_id"`
	ConfigDigest  string `json:"config_digest"`
	TargetSPKI    string `json:"target_key_spki_fingerprint"`
	GrantsDigest  string `json:"grants_digest"`
	SharesDigest  string `json:"share_envelopes_digest"`
	RequestDigest string `json:"request_digest"`
	IssuedAt      int64  `json:"issued_at"`
	ExpiresAt     int64  `json:"expires_at"`
	Version       uint   `json:"server_key_version"`
	Signature     string `json:"signature"`
}

func (d RotationDecision) fields() []string {
	return []string{d.AccountID, d.OrgID, d.OperationID, d.SessionID, d.ConfigDigest, d.TargetSPKI, d.GrantsDigest, d.SharesDigest}
}
func (d RotationDecision) Canonical() string {
	fields := append(d.fields(), d.Challenge, d.DeviceID, d.TokenID, strconv.FormatInt(d.SessionStart, 10), d.RequestDigest, strconv.FormatInt(d.IssuedAt, 10), strconv.FormatInt(d.ExpiresAt, 10), strconv.FormatUint(uint64(d.Version), 10))
	return archiveShareCanonical("dragpass.archive.quorum.rotation.decision|1", fields...)
}
func rotationHash(b []byte) string { sum := sha256.Sum256(b); return hex.EncodeToString(sum[:]) }
func rotationDigest(domain string, fields ...string) string {
	return rotationHash([]byte(archiveShareCanonical(domain, fields...)))
}

func (r ArchiveRotationRequest) Commitment(account, targetSPKI string) (RotationDecision, error) {
	var d RotationDecision
	for _, id := range []string{account, r.OrgID, r.OperationID, r.SessionID} {
		if err := requireMessageUUID(id, "rotation.identity"); err != nil {
			return d, err
		}
	}
	for _, value := range []string{r.ConfigDigest, targetSPKI} {
		if err := requireMessageDigest(value, "rotation.digest"); err != nil {
			return d, err
		}
	}
	if len(r.Shares) < 2 || len(r.Shares) > 255 || r.Grants == nil || len(r.Grants) > 97 {
		return d, newValidationError("rotation", "invalid batch or share count")
	}
	shares := []string{strconv.Itoa(len(r.Shares))}
	prev := 0
	for _, s := range r.Shares {
		if s.Index <= prev || s.Index > 255 {
			return d, newValidationError("shares", "must have ascending unique share indices")
		}
		prev = s.Index
		if err := requireMessageUUID(s.AccountID, "share.account_id"); err != nil {
			return d, err
		}
		for _, v := range []string{s.WrappedKey, s.Ciphertext} {
			b, err := base64.StdEncoding.DecodeString(v)
			if err != nil || len(b) == 0 || base64.StdEncoding.EncodeToString(b) != v {
				return d, newValidationError("share.envelope", "invalid Base64")
			}
		}
		shares = append(shares, s.AccountID, strconv.Itoa(s.Index), ArchiveShareEnvelopeDigest(s.Index, s.WrappedKey, s.Ciphertext))
	}
	grants := []string{strconv.Itoa(len(r.Grants))}
	seen := make(map[string]bool, len(r.Grants))
	for _, g := range r.Grants {
		if err := requireMessageUUID(g.ID, "grant_id"); err != nil {
			return d, err
		}
		if seen[g.ID] {
			return d, newValidationError("grant_id", "duplicate")
		}
		seen[g.ID] = true
		if err := validateGrantContext(g.Context(r.OrgID), "grant"); err != nil {
			return d, err
		}
		raw, err := base64.StdEncoding.DecodeString(g.Wrapped)
		if err != nil || len(raw) != 256 || base64.StdEncoding.EncodeToString(raw) != g.Wrapped {
			return d, newValidationError("grant", "invalid RSA-2048 ciphertext")
		}
		grants = append(grants, g.ID, g.GroupID, strconv.Itoa(g.Version), rotationHash(raw))
	}
	d = RotationDecision{AccountID: account, OrgID: r.OrgID, OperationID: r.OperationID, SessionID: r.SessionID, ConfigDigest: r.ConfigDigest, TargetSPKI: targetSPKI, GrantsDigest: rotationDigest("dragpass.archive.quorum.rotation.grants|1", grants...), SharesDigest: rotationDigest("dragpass.archive.quorum.rotation.shares|1", shares...)}
	d.RequestDigest = rotationDigest("dragpass.archive.quorum.rotation.request|1", d.fields()...)
	return d, nil
}

type ArchiveRotationPrepare struct {
	ArchiveLoginScope
	Request      ArchiveRotationRequest `json:"request"`
	TokenID      string                 `json:"token_id"`
	SessionStart int64                  `json:"session_issued_at_nanos,string"`
}

func (r ArchiveRotationPrepare) Validate() error {
	return validateArchiveLogin(r.TokenID, r.SessionStart)
}

type RotationPrepared struct {
	Challenge     string `json:"challenge"`
	RequestDigest string `json:"request_digest"`
	TargetSPKI    string `json:"target_key_spki_fingerprint"`
}
type ArchiveRotationExecute struct {
	ArchiveLoginScope
	Request  ArchiveRotationRequest `json:"request"`
	Decision RotationDecision       `json:"decision"`
}

func (r ArchiveRotationExecute) Validate() error {
	d := r.Decision
	if err := validateArchiveChallenge(d.Challenge); err != nil {
		return err
	}
	if err := validateArchiveLogin(d.TokenID, d.SessionStart); err != nil {
		return err
	}
	return validateArchiveDecisionValidity(d.SessionStart, d.IssuedAt, d.ExpiresAt, d.Version, d.Signature)
}

type RotationGrantOutput struct {
	ID          string `json:"grant_id"`
	Wrapped     string `json:"wrapped_old_group_dek"`
	Fingerprint string `json:"recipient_key_fingerprint"`
}
type RotationOutputs struct {
	Grants []RotationGrantOutput `json:"grants"`
}
