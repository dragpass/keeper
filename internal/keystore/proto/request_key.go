// request_key.go — per-device request-signing key payloads.
//
//   - request_key_generate : generate an Ed25519 keypair (if missing).
//     force_rotate is unsupported (rotation lives under
//     rotate_request_key_prepare / promote / abort).
//   - request_key_status   : whether an active key exists + public key +
//     key_id (currently the fingerprint).
//   - sign_request         : sign a canonical request string with the
//     active key.
//
// canonical_request inputs are metadata only (method/path/timestamp/...)
// — never plaintext payload / token / secret itself (security
// requirement).
//
// The signature response is base64(64B Ed25519 signature). publickey is
// base64(32B raw).

package proto

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"strconv"
	"strings"
)

type RequestKeyGenerateRequest struct {
	// force_rotate is ignored through P4. rotate_request_key_prepare is
	// added in P4 as a separate action.
	ForceRotate bool `json:"force_rotate,omitempty"`
}

func (r RequestKeyGenerateRequest) Validate() error { return nil }

type RequestKeyGenerateResponseData struct {
	PublicKey   string `json:"publickey"`
	Fingerprint string `json:"fingerprint"` // hex(sha256(base64 pub))
}

type RequestKeyStatusRequest struct{}

func (r RequestKeyStatusRequest) Validate() error { return nil }

type RequestKeyStatusResponseData struct {
	HasActive   bool   `json:"has_active"`
	PublicKey   string `json:"publickey,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

type SignRequestRequest struct {
	CanonicalRequest string `json:"canonical_request"`
}

func (r SignRequestRequest) Validate() error {
	return requireString(r.CanonicalRequest, "canonical_request")
}

// SignAppSessionRefreshRequest carries the fields of a dp-app-refresh-v1
// canonical. Keeper joins them itself, so a caller cannot get any other
// string signed through this action. The Local RPC route fills Origin from
// the paired session; a Native Messaging caller names it.
type SignAppSessionRefreshRequest struct {
	Origin     string `json:"origin"`
	Timestamp  string `json:"timestamp"`
	Nonce      string `json:"nonce"`
	BodySHA256 string `json:"body_sha256"`
	AppBinding string `json:"app_binding"`
	DeviceID   string `json:"device_id"`
}

func (r SignAppSessionRefreshRequest) Validate() error {
	if u, err := url.Parse(r.Origin); err != nil || (u.Scheme != "https" && u.Scheme != "http") ||
		u.Host == "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil ||
		u.String() != r.Origin {
		return newValidationError("origin", "must be a scheme://host origin")
	}
	if seconds, err := strconv.ParseInt(r.Timestamp, 10, 64); err != nil || seconds <= 0 ||
		strconv.FormatInt(seconds, 10) != r.Timestamp {
		return newValidationError("timestamp", "must be unix seconds")
	}
	if nonce, err := base64.RawURLEncoding.DecodeString(r.Nonce); err != nil || len(nonce) < 16 || len(r.Nonce) > 128 {
		return newValidationError("nonce", "must be base64url of at least 16 bytes")
	}
	if digest, err := hex.DecodeString(r.BodySHA256); err != nil || len(digest) != sha256.Size ||
		r.BodySHA256 != strings.ToLower(r.BodySHA256) {
		return newValidationError("body_sha256", "must be lowercase hex SHA-256")
	}
	if binding, err := base64.RawURLEncoding.DecodeString(r.AppBinding); err != nil || len(binding) != sha256.Size {
		return newValidationError("app_binding", "must be base64url SHA-256")
	}
	if len(r.DeviceID) < 8 || len(r.DeviceID) > 128 || strings.ContainsAny(r.DeviceID, "\r\n") {
		return newValidationError("device_id", "invalid")
	}
	return nil
}

type SignRequestResponseData struct {
	Signature   string `json:"signature"`   // base64(64B Ed25519 signature)
	PublicKey   string `json:"publickey"`   // base64(32B Ed25519 public)
	Fingerprint string `json:"fingerprint"` // hex(sha256(base64 pub))
}

// ──────────────────────────────────────────────────────────────────────
// Request-signing key rotation.
// ──────────────────────────────────────────────────────────────────────

// RotateRequestKeyPrepareRequest — sign the server's challenge_token with
// both the OLD and NEW priv. Stores the result + pending key.
type RotateRequestKeyPrepareRequest struct {
	ChallengeToken string `json:"challenge_token"`
}

func (r RotateRequestKeyPrepareRequest) Validate() error {
	return requireString(r.ChallengeToken, "challenge_token")
}

type RotateRequestKeyPrepareResponseData struct {
	NewPublicKey string `json:"new_public_key"`
	OldSignature string `json:"old_signature"`
	NewSignature string `json:"new_signature"`
	OldKeyID     string `json:"old_key_id,omitempty"` // fingerprint of the active slot (Extension forwards to server as-is)
}

// RotateRequestKeyPromoteRequest — called after the server's complete
// response. Empty payload (the server does not return a
// confirmation_token in this simpler P4a model).
type RotateRequestKeyPromoteRequest struct{}

func (r RotateRequestKeyPromoteRequest) Validate() error { return nil }

type RotateRequestKeyPromoteResponseData struct {
	Promoted        bool   `json:"promoted"`
	ActivePublicKey string `json:"active_public_key"`
	Fingerprint     string `json:"fingerprint"`
}

// RotateRequestKeyAbortRequest — force-empties the pending slot
// (idempotent).
type RotateRequestKeyAbortRequest struct{}

func (r RotateRequestKeyAbortRequest) Validate() error { return nil }

type RotateRequestKeyAbortResponseData struct {
	Aborted bool `json:"aborted"` // whether something was actually wiped (false for an idempotent call)
}
