package proto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"strconv"
	"unicode/utf8"
)

const CurrentGroupDisplayPrepareMaxRequestBytes = 16 * 1024

// CurrentGroupDisplayPrepareRequest names ciphertext and the receiving frame.
// The active account and device are read from Keeper, not supplied by a page.
type CurrentGroupDisplayPrepareRequest struct {
	GroupHandle           string `json:"group_handle"`
	Token                 string `json:"token"`
	TokenAADB64           string `json:"token_aad_b64,omitempty"`
	IVB64                 string `json:"iv_b64"`
	CiphertextB64         string `json:"ciphertext_b64"`
	FramePublicKeySPKIB64 string `json:"frame_public_key_spki_b64"`
	TokenID               string `json:"token_id"`
	// The JWT nanosecond value exceeds JavaScript's exact integer range.
	SessionIssuedAtNanos string `json:"session_issued_at_nanos"`
}

func (r CurrentGroupDisplayPrepareRequest) Validate() error {
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
	frameSPKI, err := requireBase64(r.FramePublicKeySPKIB64, "frame_public_key_spki_b64")
	if err != nil {
		return err
	}
	if len(frameSPKI) < 64 || len(frameSPKI) > 256 {
		return newValidationError("frame_public_key_spki_b64", "decoded length must be within 64..256 bytes")
	}
	parsed, err := x509.ParsePKIXPublicKey(frameSPKI)
	if err != nil {
		return newValidationError("frame_public_key_spki_b64", "must be a P-256 public key")
	}
	key, ok := parsed.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P256() {
		return newValidationError("frame_public_key_spki_b64", "must be a P-256 public key")
	}
	if err := requireMessageUUID(r.TokenID, "token_id"); err != nil {
		return err
	}
	nanos, err := strconv.ParseInt(r.SessionIssuedAtNanos, 10, 64)
	if err != nil || nanos <= 0 || strconv.FormatInt(nanos, 10) != r.SessionIssuedAtNanos {
		return newValidationError("session_issued_at_nanos", "must be a canonical positive int64 decimal string")
	}
	return nil
}

type CurrentGroupDisplayPrepareResponseData struct {
	Challenge       string `json:"challenge"`
	GroupID         string `json:"group_id"`
	DekVersion      int    `json:"dek_version"`
	GrantDigest     string `json:"grant_digest"`
	OperationDigest string `json:"operation_digest"`
	FrameKeyDigest  string `json:"frame_key_digest"`
}
