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

// MLSAccountOnlineDecisionDomain is the first canonical field of the per-call
// online decision for the account-level MLS actions (lv78 A1b). It differs
// from ChatOnlineDecisionDomain, so neither decision verifies as the other.
const MLSAccountOnlineDecisionDomain = "dragpass.mls.account_online|1"

// MLSAccountOnlineDecisionTTLSeconds is the decision's lifetime the API signs
// and the challenge deadline Keeper keeps, as for the chat decision.
const MLSAccountOnlineDecisionTTLSeconds = 10

// MLSAccountOnlineDecision is the API's signed answer that this App session
// may run one account-level MLS action on one target now. It names no
// conversation; Target is the action's own object: "device:<id>",
// "takeover:<request id>" or "org:<id>/account:<removed id>".
type MLSAccountOnlineDecision struct {
	Challenge            string `json:"challenge"`
	AccountID            string `json:"account_id"`
	DeviceID             string `json:"device_id"`
	TokenID              string `json:"token_id"`
	SessionIssuedAtNanos int64  `json:"session_issued_at_nanos,string"`
	Action               string `json:"action"`
	Target               string `json:"target"`
	RequestCommitment    string `json:"request_commitment"`
	IssuedAt             int64  `json:"issued_at"`
	ExpiresAt            int64  `json:"expires_at"`
	ServerKeyVersion     uint   `json:"server_key_version"`
	Signature            string `json:"signature"`
}

// MLSAccountOnlineDecisionCanonical is the signed byte string, identical to
// the API's MLSAccountOnlineDecisionCanonical (golden vector in the test).
func MLSAccountOnlineDecisionCanonical(d MLSAccountOnlineDecision) string {
	return archiveShareCanonical(MLSAccountOnlineDecisionDomain,
		d.Challenge, d.AccountID, d.DeviceID, d.TokenID,
		strconv.FormatInt(d.SessionIssuedAtNanos, 10), d.Action, d.Target,
		d.RequestCommitment,
		strconv.FormatInt(d.IssuedAt, 10), strconv.FormatInt(d.ExpiresAt, 10),
		strconv.FormatUint(uint64(d.ServerKeyVersion), 10))
}

// MLSAccountOnlinePrepareRequest asks Keeper for a challenge for one
// account-level call. Request is the exact JSON the action takes. The leaf
// handover request does not name the takeover request it answers, so the App
// names it in TakeoverRequestID; no other action takes it.
type MLSAccountOnlinePrepareRequest struct {
	Action               string          `json:"action"`
	Request              json.RawMessage `json:"request"`
	TokenID              string          `json:"token_id"`
	SessionIssuedAtNanos int64           `json:"session_issued_at_nanos,string"`
	TakeoverRequestID    string          `json:"takeover_request_id,omitempty"`
}

// MLSAccountOnlinePrepareResponseData is what the App sends the API, with the
// target Keeper derived from the request, which the decision must repeat.
type MLSAccountOnlinePrepareResponseData struct {
	Challenge         string `json:"challenge"`
	RequestCommitment string `json:"request_commitment"`
	Target            string `json:"target"`
}

// MLSAccountOnlineExecuteRequest runs the prepared call with the API's
// decision. Request must be byte for byte the request that was prepared.
type MLSAccountOnlineExecuteRequest struct {
	Action   string                    `json:"action"`
	Request  json.RawMessage           `json:"request"`
	Decision *MLSAccountOnlineDecision `json:"decision"`
}

// MLSAccountOnlineRequestCommitment is the keyed commitment to one call and
// its target, under its own domain. The key is drawn per challenge and never
// leaves Keeper.
func MLSAccountOnlineRequestCommitment(key []byte, action, target string, request []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(archiveShareCanonical("dragpass.mls.account_online.request|1", action, target, string(request))))
	return hex.EncodeToString(mac.Sum(nil))
}

// Validate checks the decision's shape before anything is compared or
// verified: a 32-byte challenge, lowercase UUID identities, a target, a
// commitment, the fixed lifetime and a named key version.
// MLSAccountOnlineTargetMaxLen bounds a decision's target. The longest is a
// handover's, which names the takeover request, the new device, its key
// fingerprint and the request's expiry (187 bytes for a ten-digit expiry).
const MLSAccountOnlineTargetMaxLen = 256

func (d MLSAccountOnlineDecision) Validate() error {
	b, err := base64.RawURLEncoding.DecodeString(d.Challenge)
	if err != nil || len(b) != 32 || base64.RawURLEncoding.EncodeToString(b) != d.Challenge {
		return newValidationError("decision.challenge", "invalid challenge")
	}
	for _, id := range []string{d.AccountID, d.DeviceID, d.TokenID} {
		if err := requireMessageUUID(id, "decision.identity"); err != nil {
			return err
		}
	}
	if err := requireMessageDigest(d.RequestCommitment, "decision.request_commitment"); err != nil {
		return err
	}
	if d.Action == "" || d.Target == "" || len(d.Target) > MLSAccountOnlineTargetMaxLen || d.SessionIssuedAtNanos <= 0 || d.IssuedAt <= 0 ||
		d.ExpiresAt-d.IssuedAt != MLSAccountOnlineDecisionTTLSeconds ||
		d.ServerKeyVersion == 0 || d.ServerKeyVersion > math.MaxUint32 {
		return newValidationError("decision", "invalid action, target, validity or version")
	}
	if b, err := base64.StdEncoding.DecodeString(d.Signature); err != nil || len(b) == 0 {
		return newValidationError("decision.signature", "invalid signature")
	}
	return nil
}
