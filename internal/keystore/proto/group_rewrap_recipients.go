package proto

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
)

// RewrapRecipientCommitment names one ordered output of a Group DEK rewrap.
// KeyFingerprint is the canonical SPKI digest, not the stored PEM-byte pin.
type RewrapRecipientCommitment struct {
	Kind           string `json:"kind"`
	AccountID      string `json:"account_id,omitempty"`
	KeyFingerprint string `json:"key_fingerprint"`
}

// RewrapRecipientsDigest binds every recipient and its position. The domain
// string prevents the digest from being confused with another signed field.
func RewrapRecipientsDigest(recipients []RewrapRecipientCommitment) (string, error) {
	if len(recipients) == 0 || len(recipients) > 64 {
		return "", errors.New("invalid rewrap recipient count")
	}
	for _, recipient := range recipients {
		switch recipient.Kind {
		case "account":
			if recipient.AccountID == "" {
				return "", errors.New("account recipient requires account id")
			}
		case "archive", "self":
			if recipient.AccountID != "" {
				return "", errors.New("resource recipient cannot name an account")
			}
		default:
			return "", errors.New("invalid rewrap recipient kind")
		}
		if len(recipient.KeyFingerprint) != 64 {
			return "", errors.New("invalid rewrap key fingerprint")
		}
		decoded, err := hex.DecodeString(recipient.KeyFingerprint)
		if err != nil || hex.EncodeToString(decoded) != recipient.KeyFingerprint {
			return "", errors.New("invalid rewrap key fingerprint")
		}
	}
	canonical, err := json.Marshal(struct {
		Domain     string                      `json:"domain"`
		Recipients []RewrapRecipientCommitment `json:"recipients"`
	}{Domain: "dragpass:group-rewrap-recipients:v1", Recipients: recipients})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}
