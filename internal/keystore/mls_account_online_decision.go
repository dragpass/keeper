package keystore

import (
	"crypto/hmac"
	"encoding/base64"
	"encoding/json"
	"io"
	"strconv"
	"time"

	"github.com/dragpass/keeper/internal/keystore/dispatch"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/secure"
)

// accountOnlineScope is the part of an account-level request the target is
// derived from. Each action reads only its own fields.
type accountOnlineScope struct {
	AccountID        string `json:"account_id"`
	DeviceID         string `json:"device_id"`
	OrgID            string `json:"org_id"`
	RemovedAccountID string `json:"removed_account_id"`
	AdminAccountID   string `json:"admin_account_id"`
	// mls_leaf_handover_sign: what the handover statement signs besides
	// this device's own leaf.
	NewDeclaration struct {
		AccountID               string `json:"account_id"`
		DeviceID                string `json:"device_id"`
		SignatureKeyFingerprint string `json:"signature_key_fingerprint"`
	} `json:"new_declaration"`
	ExpiresAt int64 `json:"expires_at"`
}

// MLSHandoverOnlineTarget names one takeover request together with the
// content a handover for it signs: the new device, its leaf key fingerprint
// and the request's expiry. The API derives the same string from its stored
// request (ariadne mlsHandoverOnlineTarget), so a decision for one request
// admits no handover of other content (lv78 A1b review A1).
func MLSHandoverOnlineTarget(takeover, newDevice, newFingerprint string, expiresAt int64) string {
	return "takeover:" + takeover + "/new_device:" + newDevice + "/new_fp:" + newFingerprint +
		"/expires_at:" + strconv.FormatInt(expiresAt, 10)
}

func isLowerHex64(value string) bool {
	if len(value) != 64 {
		return false
	}
	for i := 0; i < len(value); i++ {
		if c := value[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// accountOnlineTarget derives the decision's target from the request, against
// this Keeper's own sign-in and device, as the API's issuer names it
// (ariadne mlsAccountAuthorities). ok is false for a call no decision could
// admit: a request for another account or another device's leaf.
func accountOnlineTarget(action string, request []byte, takeover, account, device string) (string, bool) {
	var scope accountOnlineScope
	if err := json.Unmarshal(request, &scope); err != nil {
		return "", false
	}
	if action != proto.ActionMLSLeafHandoverSign && takeover != "" {
		return "", false
	}
	switch action {
	case proto.ActionMLSLeafDeclare, proto.MLSKeyPackageGenerate:
		// The leaf and its KeyPackages are this device's own.
		if scope.AccountID != account || scope.DeviceID != device {
			return "", false
		}
		return "device:" + device, true
	case proto.ActionMLSLeafPromote:
		return "device:" + device, true
	case proto.MLSDeviceRevokeSign:
		if scope.AccountID != account || !proto.ChatOnlineUUID(scope.DeviceID) {
			return "", false
		}
		return "device:" + scope.DeviceID, true
	case proto.ActionMLSLeafHandoverSign:
		// The handover request does not name its takeover request; the App
		// does. The target also carries what the handover signs, which the
		// API compares with the request it stores.
		decl := scope.NewDeclaration
		if scope.AccountID != account || decl.AccountID != account || !proto.ChatOnlineUUID(takeover) ||
			!proto.ChatOnlineUUID(decl.DeviceID) || !isLowerHex64(decl.SignatureKeyFingerprint) || scope.ExpiresAt <= 0 {
			return "", false
		}
		return MLSHandoverOnlineTarget(takeover, decl.DeviceID, decl.SignatureKeyFingerprint, scope.ExpiresAt), true
	case proto.OrgMemberRemovalSign:
		if scope.AdminAccountID != account || !proto.ChatOnlineUUID(scope.OrgID) || !proto.ChatOnlineUUID(scope.RemovedAccountID) {
			return "", false
		}
		return "org:" + scope.OrgID + "/account:" + scope.RemovedAccountID, true
	}
	return "", false
}

// PrepareMLSAccountOnline mints a challenge for one account-level MLS call of
// the App (lv78 A1b), with the target Keeper derived from the request. Its
// challenges live apart from the chat ones.
func (a *App) PrepareMLSAccountOnline(loginGeneration string, in proto.MLSAccountOnlinePrepareRequest) proto.BaseResponse {
	a.requestMu.Lock()
	defer a.requestMu.Unlock()
	if !dispatch.AccountOnlineDecisionRequired(in.Action) || in.SessionIssuedAtNanos <= 0 || !proto.ChatOnlineUUID(in.TokenID) {
		return onlineDecisionRefused()
	}
	binding, found, err := keychain.GetAccountBinding(a.Store)
	if err != nil || !found || binding.SignedOut || binding.Generation == 0 {
		return onlineDecisionRefused()
	}
	device, found, err := keychain.GetDeviceID(a.Store)
	if err != nil || !found || device == "" {
		return onlineDecisionRefused()
	}
	target, ok := accountOnlineTarget(in.Action, in.Request, in.TakeoverRequestID, binding.AccountID, device)
	if !ok {
		return onlineDecisionRefused()
	}
	var random [64]byte
	if _, err := io.ReadFull(a.Rand, random[:]); err != nil {
		return onlineDecisionRefused()
	}
	defer secure.Zeroize(random[:])
	c := chatOnlineContext{
		accountID: binding.AccountID, deviceID: device, tokenID: in.TokenID,
		sessionStartNanos: in.SessionIssuedAtNanos, bindingGeneration: binding.Generation,
		loginGeneration: loginGeneration, action: in.Action, target: target,
	}
	copy(c.commitmentKey[:], random[32:])
	c.commitment = proto.MLSAccountOnlineRequestCommitment(c.commitmentKey[:], in.Action, target, in.Request)
	challenge := base64.RawURLEncoding.EncodeToString(random[:32])
	if !a.accountOnline.put(challenge, c, a.Clock()) {
		return onlineDecisionRefused()
	}
	return proto.BaseResponse{Success: true, Data: proto.MLSAccountOnlinePrepareResponseData{
		Challenge: challenge, RequestCommitment: c.commitment, Target: target,
	}}
}

// ExecuteMLSAccountOnline runs one prepared account-level call with the API's
// decision, in the same phases as ExecuteChatOnline: (a) shape, window,
// bindings, signature under the account domain and the sign-in re-read, then
// the one-shot consume; (b) the action through the ordinary chat gate,
// marked as admitted by an account decision; (c) the challenge deadline and
// expiry again, withholding the output if either passed.
func (a *App) ExecuteMLSAccountOnline(session, epoch, loginGeneration string, in proto.MLSAccountOnlineExecuteRequest) proto.BaseResponse {
	a.requestMu.Lock()
	defer a.requestMu.Unlock()
	if in.Decision == nil || in.Decision.Validate() != nil || a.ServerKeyVerifier == nil {
		return onlineDecisionRefused()
	}
	decision := *in.Decision
	now := a.Clock()
	if !accountOnlineWindowHolds(decision, now) {
		return onlineDecisionRefused()
	}
	entry, found := a.accountOnline.peek(decision.Challenge, now)
	c := entry.context
	if !found || !accountOnlineBindingMatches(c, decision, in, loginGeneration) {
		return onlineDecisionRefused()
	}
	if err := a.ServerKeyVerifier.Verify(proto.MLSAccountOnlineDecisionCanonical(decision), decision.Signature, decision.ServerKeyVersion); err != nil {
		return onlineDecisionRefused()
	}
	binding, found, err := keychain.GetAccountBinding(a.Store)
	if err != nil || !found || binding.SignedOut || binding.AccountID != c.accountID || binding.Generation != c.bindingGeneration {
		return onlineDecisionRefused()
	}
	device, found, err := keychain.GetDeviceID(a.Store)
	if err != nil || !found || device != c.deviceID {
		return onlineDecisionRefused()
	}
	now = a.Clock()
	consumed, ok := a.accountOnline.consume(decision.Challenge, now)
	if !ok || consumed.context != c || !accountOnlineWindowHolds(decision, now) {
		return onlineDecisionRefused()
	}

	frame, err := json.Marshal(struct {
		Action  string          `json:"action"`
		Payload json.RawMessage `json:"payload"`
	}{Action: in.Action, Payload: in.Request})
	if err != nil {
		return onlineDecisionRefused()
	}
	defer secure.Zeroize(frame)
	caller := chatRuntimeCaller{app: true, session: session, epoch: epoch,
		loginGeneration: loginGeneration, chatWork: true, accountOnlineDecision: true}
	response := dispatch.HandleRequestGatedAfter(a.Logger, a.HandlersDeps(), frame, a.chatRuntimeGate(caller), a.chatRuntimeAfter(caller))
	if chatOnlineAfterWork != nil {
		chatOnlineAfterWork()
	}
	now = a.Clock()
	if !now.Before(entry.deadline) || now.Unix() >= decision.ExpiresAt {
		withheld := onlineOutputWithheld()
		withheld.RequestID = response.RequestID
		return withheld
	}
	return response
}

func accountOnlineWindowHolds(d proto.MLSAccountOnlineDecision, now time.Time) bool {
	return d.IssuedAt <= now.Unix()+proto.DisplayDecisionClockSkewSeconds && now.Unix() < d.ExpiresAt
}

// accountOnlineBindingMatches compares every field the decision binds with
// what the challenge was minted for and with the call being executed.
func accountOnlineBindingMatches(c chatOnlineContext, d proto.MLSAccountOnlineDecision, in proto.MLSAccountOnlineExecuteRequest, loginGeneration string) bool {
	commitment := proto.MLSAccountOnlineRequestCommitment(c.commitmentKey[:], in.Action, c.target, in.Request)
	return c.target != "" &&
		hmac.Equal([]byte(commitment), []byte(c.commitment)) &&
		hmac.Equal([]byte(d.RequestCommitment), []byte(c.commitment)) &&
		in.Action == c.action && d.Action == c.action && d.Target == c.target &&
		d.AccountID == c.accountID && d.DeviceID == c.deviceID &&
		d.TokenID == c.tokenID && d.SessionIssuedAtNanos == c.sessionStartNanos &&
		loginGeneration == c.loginGeneration
}
