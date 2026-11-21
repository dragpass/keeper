package proto

import (
	"errors"
	"strconv"
)

// ReconfigurationSplitDecision is the v2 wire payload. The target key is the
// staged pair to split. The active key contributes only its SPKI fingerprint.
type ReconfigurationSplitDecision struct {
	Challenge                string                  `json:"challenge"`
	AccountID                string                  `json:"account_id"`
	DeviceID                 string                  `json:"device_id"`
	TokenID                  string                  `json:"token_id"`
	SessionIssuedAtNanos     int64                   `json:"session_issued_at_nanos,string"`
	OrgID                    string                  `json:"org_id"`
	OperationID              string                  `json:"operation_id"`
	Kind                     string                  `json:"kind"`
	ConfigDigest             string                  `json:"config_digest"`
	SourceConfigDigest       string                  `json:"source_config_digest"`
	TargetKeyFingerprint     string                  `json:"target_key_fingerprint"`
	TargetKeySPKIFingerprint string                  `json:"target_key_spki_fingerprint"`
	ActiveKeySPKIFingerprint string                  `json:"active_key_spki_fingerprint"`
	ThresholdN               int                     `json:"threshold_n"`
	Recipients               []ArchiveSplitRecipient `json:"recipients"`
	RequestDigest            string                  `json:"request_digest"`
	IssuedAt                 int64                   `json:"issued_at"`
	ExpiresAt                int64                   `json:"expires_at"`
	ServerKeyVersion         uint                    `json:"server_key_version"`
	Signature                string                  `json:"signature"`
}

// Canonical encodes the bytes covered by the v2 split signature.
func (d ReconfigurationSplitDecision) Canonical() (string, error) {
	if d.Kind != "reconfiguration" {
		return "", errors.New("split decision v2 requires reconfiguration kind")
	}
	fields := []string{d.Challenge, d.AccountID, d.DeviceID, d.TokenID,
		strconv.FormatInt(d.SessionIssuedAtNanos, 10), d.OrgID, d.OperationID, d.Kind,
		d.ConfigDigest, d.SourceConfigDigest, d.TargetKeyFingerprint, d.TargetKeySPKIFingerprint,
		d.ActiveKeySPKIFingerprint, strconv.Itoa(d.ThresholdN), strconv.Itoa(len(d.Recipients))}
	for _, r := range d.Recipients {
		fields = append(fields, r.AccountID, r.KeyFingerprint)
	}
	fields = append(fields, d.RequestDigest, strconv.FormatInt(d.IssuedAt, 10),
		strconv.FormatInt(d.ExpiresAt, 10), strconv.FormatUint(uint64(d.ServerKeyVersion), 10))
	return archiveShareCanonical("dragpass.archive.split.decision|2", fields...), nil
}
