package proto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math"
	"strconv"
)

// ChatOnlineDecisionDomain is the first canonical field of the per-call App
// MLS online decision (lv78 D1); the version follows it.
const ChatOnlineDecisionDomain = "dragpass.chat.online|1"

// ChatOnlineDecision is the API's signed answer that this App session may run
// one protected MLS action on one conversation now. The API signs it with the
// versioned server key Keeper already pins; Keeper verifies it, matches every
// bound field and consumes the challenge it minted before the action runs.
type ChatOnlineDecision struct {
	Challenge            string `json:"challenge"`
	AccountID            string `json:"account_id"`
	DeviceID             string `json:"device_id"`
	TokenID              string `json:"token_id"`
	SessionIssuedAtNanos int64  `json:"session_issued_at_nanos,string"`
	Action               string `json:"action"`
	OrgID                string `json:"org_id"`
	ConversationID       string `json:"conversation_id"`
	RequestCommitment    string `json:"request_commitment"`
	IssuedAt             int64  `json:"issued_at"`
	ExpiresAt            int64  `json:"expires_at"`
	ServerKeyVersion     uint   `json:"server_key_version"`
	Signature            string `json:"signature"`
}

// ChatOnlineDecisionCanonical is the signed byte string, identical to the
// API's OnlineDecisionCanonical (golden vector in the test).
func ChatOnlineDecisionCanonical(d ChatOnlineDecision) string {
	return archiveShareCanonical(ChatOnlineDecisionDomain,
		d.Challenge, d.AccountID, d.DeviceID, d.TokenID,
		strconv.FormatInt(d.SessionIssuedAtNanos, 10), d.Action, d.OrgID,
		d.ConversationID, d.RequestCommitment,
		strconv.FormatInt(d.IssuedAt, 10), strconv.FormatInt(d.ExpiresAt, 10),
		strconv.FormatUint(uint64(d.ServerKeyVersion), 10))
}

// ChatOnlineDecisionTTLSeconds is the decision's lifetime the API signs and
// the challenge deadline Keeper keeps (lv78 D2). It is an upper bound, not a
// window in which work may run after a revocation.
const ChatOnlineDecisionTTLSeconds = 10

// ChatOnlinePrepareRequest asks Keeper for a challenge for one protected
// call. Request is the exact JSON the action takes; Keeper keeps only a keyed
// commitment to it. TokenID and SessionIssuedAtNanos name the App session
// that will ask the API, which the decision must repeat.
type ChatOnlinePrepareRequest struct {
	Action               string          `json:"action"`
	Request              json.RawMessage `json:"request"`
	TokenID              string          `json:"token_id"`
	SessionIssuedAtNanos int64           `json:"session_issued_at_nanos,string"`
}

// ChatOnlinePrepareResponseData is what the App sends the API.
type ChatOnlinePrepareResponseData struct {
	Challenge         string `json:"challenge"`
	RequestCommitment string `json:"request_commitment"`
}

// ChatOnlineExecuteRequest runs the prepared call with the API's decision.
// Request must be byte for byte the request that was prepared.
type ChatOnlineExecuteRequest struct {
	Action   string              `json:"action"`
	Request  json.RawMessage     `json:"request"`
	Decision *ChatOnlineDecision `json:"decision"`
}

// ChatOnlineRequestCommitment is the keyed commitment to one call. The key
// is drawn per challenge and never leaves Keeper, so the API learns nothing
// it could match against a guessed request.
func ChatOnlineRequestCommitment(key []byte, action string, request []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(archiveShareCanonical("dragpass.chat.online.request|1", action, string(request))))
	return hex.EncodeToString(mac.Sum(nil))
}

// ChatOnlineUUID reports whether value is a non-nil lowercase UUID, the form
// every identity in the decision takes.
func ChatOnlineUUID(value string) bool {
	return requireMessageUUID(value, "id") == nil
}

// Validate checks the decision's shape before anything is compared or
// verified: a 32-byte challenge, lowercase UUID identities, a commitment, the
// fixed lifetime and a named key version (no "active key" fallback).
func (d ChatOnlineDecision) Validate() error {
	b, err := base64.RawURLEncoding.DecodeString(d.Challenge)
	if err != nil || len(b) != 32 || base64.RawURLEncoding.EncodeToString(b) != d.Challenge {
		return newValidationError("decision.challenge", "invalid challenge")
	}
	for _, id := range []string{d.AccountID, d.DeviceID, d.TokenID, d.OrgID, d.ConversationID} {
		if err := requireMessageUUID(id, "decision.identity"); err != nil {
			return err
		}
	}
	if err := requireMessageDigest(d.RequestCommitment, "decision.request_commitment"); err != nil {
		return err
	}
	if d.Action == "" || d.SessionIssuedAtNanos <= 0 || d.IssuedAt <= 0 ||
		d.ExpiresAt-d.IssuedAt != ChatOnlineDecisionTTLSeconds ||
		d.ServerKeyVersion == 0 || d.ServerKeyVersion > math.MaxUint32 {
		return newValidationError("decision", "invalid action, validity or version")
	}
	if b, err := base64.StdEncoding.DecodeString(d.Signature); err != nil || len(b) == 0 {
		return newValidationError("decision.signature", "invalid signature")
	}
	return nil
}
