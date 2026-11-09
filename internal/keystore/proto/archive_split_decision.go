package proto

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"math"
	"strconv"
)

// ArchiveSplitRecipient is one ordered split output: the participant account
// and hex(sha256(account archive public key PEM)) it is wrapped to.
type ArchiveSplitRecipient struct {
	AccountID      string `json:"account_id"`
	KeyFingerprint string `json:"key_fingerprint"`
}

// ArchiveSplitDecision is the server-signed `archive_split` authority. It binds
// the requester's login, the exact operation, the archive key being split and
// every ordered recipient, so a paired App cannot collect shares under keys of
// its own choosing.
type ArchiveSplitDecision struct {
	Challenge                 string                  `json:"challenge"`
	AccountID                 string                  `json:"account_id"`
	DeviceID                  string                  `json:"device_id"`
	TokenID                   string                  `json:"token_id"`
	SessionIssuedAtNanos      int64                   `json:"session_issued_at_nanos,string"`
	OrgID                     string                  `json:"org_id"`
	OperationID               string                  `json:"operation_id"`
	ConfigDigest              string                  `json:"config_digest"`
	ArchiveKeyFingerprint     string                  `json:"archive_key_fingerprint"`
	ArchiveKeySPKIFingerprint string                  `json:"archive_key_spki_fingerprint"`
	ThresholdN                int                     `json:"threshold_n"`
	Recipients                []ArchiveSplitRecipient `json:"recipients"`
	RequestDigest             string                  `json:"request_digest"`
	IssuedAt                  int64                   `json:"issued_at"`
	ExpiresAt                 int64                   `json:"expires_at"`
	ServerKeyVersion          uint                    `json:"server_key_version"`
	Signature                 string                  `json:"signature"`
}

// ArchiveSplitDecisionCanonical is the signed string. The recipient count
// precedes the recipient pairs so the list cannot absorb a neighbouring field.
func ArchiveSplitDecisionCanonical(d ArchiveSplitDecision) string {
	fields := []string{d.Challenge, d.AccountID, d.DeviceID, d.TokenID,
		strconv.FormatInt(d.SessionIssuedAtNanos, 10), d.OrgID, d.OperationID, d.ConfigDigest,
		d.ArchiveKeyFingerprint, d.ArchiveKeySPKIFingerprint, strconv.Itoa(d.ThresholdN),
		strconv.Itoa(len(d.Recipients))}
	for _, r := range d.Recipients {
		fields = append(fields, r.AccountID, r.KeyFingerprint)
	}
	fields = append(fields, d.RequestDigest, strconv.FormatInt(d.IssuedAt, 10),
		strconv.FormatInt(d.ExpiresAt, 10), strconv.FormatUint(uint64(d.ServerKeyVersion), 10))
	return archiveShareCanonical("dragpass.archive.split.decision|1", fields...)
}

func (d ArchiveSplitDecision) Validate() error {
	if err := validateArchiveChallenge(d.Challenge); err != nil {
		return err
	}
	for _, id := range []string{d.AccountID, d.DeviceID, d.TokenID, d.OrgID, d.OperationID} {
		if err := requireMessageUUID(id, "decision.identity"); err != nil {
			return err
		}
	}
	for _, digest := range []string{d.ConfigDigest, d.ArchiveKeyFingerprint, d.ArchiveKeySPKIFingerprint, d.RequestDigest} {
		if err := requireMessageDigest(digest, "decision.digest"); err != nil {
			return err
		}
	}
	if d.ThresholdN < 2 || len(d.Recipients) < d.ThresholdN || len(d.Recipients) > 255 {
		return newValidationError("decision.recipients", "invalid threshold or recipient count")
	}
	for _, r := range d.Recipients {
		if err := requireMessageUUID(r.AccountID, "decision.recipients.account_id"); err != nil {
			return err
		}
		if err := requireMessageDigest(r.KeyFingerprint, "decision.recipients.key_fingerprint"); err != nil {
			return err
		}
	}
	return validateArchiveDecisionValidity(d.SessionIssuedAtNanos, d.IssuedAt, d.ExpiresAt, d.ServerKeyVersion, d.Signature)
}

// ArchiveSplitRequestDigest commits the exact split request without its
// decision, so a retry under a fresh decision names the same request.
// Recipient keys are committed by hex(sha256(PEM)), the fingerprint the
// server stores for account archive keys.
func ArchiveSplitRequestDigest(r ArchiveKeySplitRequest) (string, error) {
	if err := r.ValidateAuthorized(); err != nil {
		return "", err
	}
	fields := []string{r.AccountID, r.OrgID, r.OperationID, r.ConfigDigest,
		strconv.Itoa(r.ThresholdN), strconv.Itoa(len(r.RecipientPublicKeys))}
	for i, pem := range r.RecipientPublicKeys {
		fields = append(fields, r.RecipientAccountIDs[i], ArchiveRecipientFingerprint(pem))
	}
	digest := sha256.Sum256([]byte(archiveShareCanonical("dragpass.archive.split.request|1", fields...)))
	return hex.EncodeToString(digest[:]), nil
}

// ArchiveRecipientFingerprint is hex(sha256(PEM bytes as received)).
func ArchiveRecipientFingerprint(pem string) string {
	sum := sha256.Sum256([]byte(pem))
	return hex.EncodeToString(sum[:])
}

// ValidateAuthorized adds the fields a server-authorized split must name:
// the requester, the organization, the configuration digest and one distinct
// account per recipient key.
func (r ArchiveKeySplitRequest) ValidateAuthorized() error {
	if err := r.Validate(); err != nil {
		return err
	}
	if err := requireMessageUUID(r.AccountID, "account_id"); err != nil {
		return err
	}
	if err := requireMessageUUID(r.OrgID, "org_id"); err != nil {
		return err
	}
	if err := requireMessageDigest(r.ConfigDigest, "config_digest"); err != nil {
		return err
	}
	if len(r.RecipientAccountIDs) != len(r.RecipientPublicKeys) {
		return newValidationError("recipient_account_ids", "must match recipient_public_keys")
	}
	accounts := make(map[string]struct{}, len(r.RecipientAccountIDs))
	keys := make(map[string]struct{}, len(r.RecipientPublicKeys))
	for i, id := range r.RecipientAccountIDs {
		if err := requireMessageUUID(id, "recipient_account_ids"); err != nil {
			return err
		}
		fp := ArchiveRecipientFingerprint(r.RecipientPublicKeys[i])
		if _, dup := accounts[id]; dup {
			return newValidationError("recipient_account_ids", "must be distinct")
		}
		if _, dup := keys[fp]; dup {
			return newValidationError("recipient_public_keys", "must be distinct")
		}
		accounts[id], keys[fp] = struct{}{}, struct{}{}
	}
	return nil
}

type ArchiveSplitPrepareRequest struct {
	Request              ArchiveKeySplitRequest `json:"request"`
	TokenID              string                 `json:"token_id"`
	SessionIssuedAtNanos int64                  `json:"session_issued_at_nanos,string"`
}

func (r ArchiveSplitPrepareRequest) Validate() error {
	if _, err := ArchiveSplitRequestDigest(r.Request); err != nil {
		return err
	}
	return validateArchiveLogin(r.TokenID, r.SessionIssuedAtNanos)
}

type ArchiveSplitPrepareResponseData struct {
	Challenge     string `json:"challenge"`
	RequestDigest string `json:"request_digest"`
}

func validateArchiveChallenge(challenge string) error {
	b, err := base64.RawURLEncoding.DecodeString(challenge)
	if err != nil || len(b) != 32 || base64.RawURLEncoding.EncodeToString(b) != challenge {
		return newValidationError("decision.challenge", "invalid challenge")
	}
	return nil
}

func validateArchiveDecisionValidity(sessionNanos, issuedAt, expiresAt int64, version uint, signature string) error {
	if sessionNanos <= 0 || issuedAt <= 0 || expiresAt <= issuedAt || expiresAt-issuedAt != ArchiveShareDecisionTTLSeconds || version == 0 || version > math.MaxUint32 {
		return newValidationError("decision", "invalid validity or version")
	}
	if b, err := base64.StdEncoding.DecodeString(signature); err != nil || len(b) == 0 {
		return newValidationError("decision.signature", "invalid signature")
	}
	return nil
}

func validateArchiveLogin(tokenID string, sessionNanos int64) error {
	if err := requireMessageUUID(tokenID, "token_id"); err != nil {
		return err
	}
	if sessionNanos <= 0 {
		return newValidationError("session_issued_at_nanos", "must be positive")
	}
	return nil
}

// ArchiveShareProofKeyInfo is the HKDF info for a share's proof key:
// "dragpass.archive.share.proof-key|1" | len:operation_id | len:share_index.
func ArchiveShareProofKeyInfo(operationID string, shareIndex int) string {
	return archiveShareCanonical("dragpass.archive.share.proof-key|1", operationID, strconv.Itoa(shareIndex))
}
