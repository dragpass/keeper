package proto

import (
	"encoding/base64"
	"math"
	"strconv"
	"strings"
)

const ActionPersonalDEKBind = "personal_dek_bind"

type PersonalDEKBindingProof struct {
	AccountID            string `json:"account_id"`
	DeviceID             string `json:"device_id"`
	TokenID              string `json:"token_id"`
	SessionIssuedAtNanos int64  `json:"session_issued_at_nanos,string"`
	LoginGeneration      string `json:"login_generation"`
	WrappedDEKDigest     string `json:"wrapped_dek_digest"`
	IssuedAt             int64  `json:"issued_at"`
	ExpiresAt            int64  `json:"expires_at"`
	ServerKeyVersion     uint   `json:"server_key_version"`
	Signature            string `json:"signature"`
}

func PersonalDEKBindingCanonical(p PersonalDEKBindingProof) string {
	return strings.Join([]string{"dragpass.personal.dek.binding", "1", p.AccountID, p.DeviceID,
		p.TokenID, strconv.FormatInt(p.SessionIssuedAtNanos, 10), p.LoginGeneration, p.WrappedDEKDigest,
		strconv.FormatInt(p.IssuedAt, 10), strconv.FormatInt(p.ExpiresAt, 10), strconv.FormatUint(uint64(p.ServerKeyVersion), 10)}, "|")
}

type PersonalDEKBindRequest struct {
	Password        string                  `json:"password"`
	EncryptedDEKB64 string                  `json:"encrypted_dek_b64"`
	Proof           PersonalDEKBindingProof `json:"proof"`
}

func (p PersonalDEKBindingProof) Validate() error {
	for _, value := range []string{p.AccountID, p.DeviceID, p.TokenID} {
		if err := requireMessageUUID(value, "proof.identity"); err != nil {
			return err
		}
	}
	generation, err := base64.RawURLEncoding.DecodeString(p.LoginGeneration)
	if err != nil || len(generation) != 16 || base64.RawURLEncoding.EncodeToString(generation) != p.LoginGeneration {
		return newValidationError("proof.login_generation", "invalid generation")
	}
	if p.SessionIssuedAtNanos <= 0 || p.IssuedAt <= 0 || p.ExpiresAt <= p.IssuedAt || p.ExpiresAt-p.IssuedAt != 30 || p.ServerKeyVersion == 0 || p.ServerKeyVersion > math.MaxUint32 {
		return newValidationError("proof", "invalid lifetime or version")
	}
	if err := requireMessageDigest(p.WrappedDEKDigest, "proof.wrapped_dek_digest"); err != nil {
		return err
	}
	_, err = requireBase64(p.Signature, "proof.signature")
	return err
}
