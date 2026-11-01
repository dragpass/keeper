package proto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"math"
	"strconv"
	"strings"
	"unicode/utf8"
)

const PersonalDisplayDecisionTTLSeconds = 10
const PersonalDisplayPrepareMaxRequestBytes = 16 * 1024
const PersonalDisplayExecuteMaxRequestBytes = 20 * 1024

const (
	ActionPersonalDisplayPrepare = "personal_display_prepare"
	ActionPersonalDisplayExecute = "personal_display_execute"
)

type PersonalDisplayPrepareRequest struct {
	Token string `json:"token"`
	// TokenExpiry is the bound token's authenticated expiry. Keeper builds
	// the AAD from it and the signed-in account; empty means a legacy token.
	TokenExpiry           string `json:"token_expiry,omitempty"`
	IVB64                 string `json:"iv_b64"`
	CiphertextB64         string `json:"ciphertext_b64"`
	FramePublicKeySPKIB64 string `json:"frame_public_key_spki_b64"`
	TokenID               string `json:"token_id"`
	SessionIssuedAtNanos  string `json:"session_issued_at_nanos"`
}

func (r PersonalDisplayPrepareRequest) Validate() error {
	if len(r.Token) == 0 || len(r.Token) > 8192 || !utf8.ValidString(r.Token) {
		return newValidationError("token", "must be valid UTF-8 within 1..8192 bytes")
	}
	if r.TokenExpiry != "" {
		if _, err := ParseTokenExpiry(r.TokenExpiry); err != nil {
			return err
		}
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

type PersonalDisplayPrepareResponseData struct {
	Challenge       string `json:"challenge"`
	WrapDigest      string `json:"wrap_digest"`
	OperationDigest string `json:"operation_digest"`
	FrameKeyDigest  string `json:"frame_key_digest"`
}

type PersonalDisplayExecuteRequest struct {
	Prepare  PersonalDisplayPrepareRequest `json:"prepare"`
	Decision PersonalDisplayDecision       `json:"decision"`
}

func (r PersonalDisplayExecuteRequest) Validate() error {
	if err := r.Prepare.Validate(); err != nil {
		return err
	}
	return r.Decision.Validate()
}

type PersonalDisplayOperation struct {
	Challenge          [32]byte
	Token              []byte
	TokenAAD           []byte
	IV                 [12]byte
	Ciphertext         []byte
	FramePublicKeySPKI []byte
}

// PersonalDisplayOperationDigest commits to the selected ciphertext and
// receiving frame without revealing either plaintext or a personal DEK.
func PersonalDisplayOperationDigest(op PersonalDisplayOperation) [sha256.Size]byte {
	h := sha256.New()
	_, _ = h.Write([]byte("dragpass.personal.display.operation\x00\x01"))
	writeGroupDisplayDigestField(h, op.Challenge[:])
	writeGroupDisplayDigestField(h, op.Token)
	writeGroupDisplayDigestField(h, op.TokenAAD)
	writeGroupDisplayDigestField(h, op.IV[:])
	writeGroupDisplayDigestField(h, op.Ciphertext)
	writeGroupDisplayDigestField(h, op.FramePublicKeySPKI)
	var out [sha256.Size]byte
	copy(out[:], h.Sum(nil))
	return out
}

type PersonalDisplayDecision struct {
	Challenge            string `json:"challenge"`
	AccountID            string `json:"account_id"`
	DeviceID             string `json:"device_id"`
	TokenID              string `json:"token_id"`
	SessionIssuedAtNanos int64  `json:"session_issued_at_nanos,string"`
	WrapDigest           string `json:"wrap_digest"`
	OperationDigest      string `json:"operation_digest"`
	FrameKeyDigest       string `json:"frame_key_digest"`
	IssuedAt             int64  `json:"issued_at"`
	ExpiresAt            int64  `json:"expires_at"`
	ServerKeyVersion     uint   `json:"server_key_version"`
	Signature            string `json:"signature"`
}

// PersonalDisplayDecisionCanonical matches Ariadne's signed v1 statement.
func PersonalDisplayDecisionCanonical(d PersonalDisplayDecision) string {
	return strings.Join([]string{
		"dragpass.personal.display", "1", d.Challenge, d.AccountID, d.DeviceID,
		d.TokenID, strconv.FormatInt(d.SessionIssuedAtNanos, 10), d.WrapDigest,
		d.OperationDigest, d.FrameKeyDigest, strconv.FormatInt(d.IssuedAt, 10),
		strconv.FormatInt(d.ExpiresAt, 10), strconv.FormatUint(uint64(d.ServerKeyVersion), 10),
	}, "|")
}

func (d PersonalDisplayDecision) Validate() error {
	if err := requireMessageChallenge(d.Challenge, "decision.challenge"); err != nil {
		return err
	}
	challenge, _ := base64.RawURLEncoding.DecodeString(d.Challenge)
	if len(challenge) != 32 || base64.RawURLEncoding.EncodeToString(challenge) != d.Challenge {
		return newValidationError("decision.challenge", "must be canonical 32-byte Base64URL")
	}
	for _, item := range []struct{ value, field string }{
		{d.AccountID, "decision.account_id"},
		{d.DeviceID, "decision.device_id"},
		{d.TokenID, "decision.token_id"},
	} {
		if err := requireMessageUUID(item.value, item.field); err != nil {
			return err
		}
	}
	if d.SessionIssuedAtNanos <= 0 {
		return newValidationError("decision.session_issued_at_nanos", "must be positive")
	}
	for _, item := range []struct{ value, field string }{
		{d.WrapDigest, "decision.wrap_digest"},
		{d.OperationDigest, "decision.operation_digest"},
		{d.FrameKeyDigest, "decision.frame_key_digest"},
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
	if d.ExpiresAt-d.IssuedAt != PersonalDisplayDecisionTTLSeconds {
		return newValidationError("decision.expires_at", "invalid validity window")
	}
	if d.ServerKeyVersion < 1 || d.ServerKeyVersion > math.MaxUint32 {
		return newValidationError("decision.server_key_version", "must be a positive uint32")
	}
	if d.Signature == "" {
		return newValidationError("decision.signature", "must not be empty")
	}
	if _, err := base64.StdEncoding.DecodeString(d.Signature); err != nil {
		return newValidationError("decision.signature", "must be standard Base64")
	}
	return nil
}
