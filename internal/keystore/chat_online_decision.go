package keystore

import (
	"crypto/hmac"
	"encoding/base64"
	"encoding/json"
	"io"
	"sync"
	"time"

	"github.com/dragpass/keeper/internal/keystore/dispatch"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/secure"
)

// ErrCodeChatOnlineDecisionRefused answers a decision that did not admit the
// call (lv78 K2): unknown or expired challenge, a binding that does not match,
// or a signature that does not verify. The action did not run. The App learns
// nothing about which check failed.
const ErrCodeChatOnlineDecisionRefused = "chat_online_decision_refused"

// ErrCodeChatOnlineOutputWithheld answers a protected action that ran, but
// whose decision deadline or expiry passed before the answer could be
// returned (phase c). Unlike a refusal, local state the action wrote may have
// moved, so the App reads it again. The answer carries no output.
const ErrCodeChatOnlineOutputWithheld = "chat_online_output_withheld"

const (
	chatOnlineChallengeTTL = proto.ChatOnlineDecisionTTLSeconds * time.Second
	chatOnlineMaxPending   = 128
)

func onlineDecisionRefused() proto.BaseResponse {
	return proto.BaseResponse{
		Error:     "the online decision did not admit this chat action",
		ErrorCode: ErrCodeChatOnlineDecisionRefused,
	}
}

func onlineOutputWithheld() proto.BaseResponse {
	return proto.BaseResponse{
		Error:     "the chat action ran but its answer was withheld",
		ErrorCode: ErrCodeChatOnlineOutputWithheld,
	}
}

// chatOnlineContext is what a challenge was minted for. It holds identities,
// the commitment and its key; never the request itself.
type chatOnlineContext struct {
	accountID         string
	deviceID          string
	tokenID           string
	sessionStartNanos int64
	bindingGeneration uint64
	loginGeneration   string
	action            string
	orgID             string
	conversationID    string
	// target is the account-level action's object (lv78 A1b); empty for chat.
	target        string
	commitment    string
	commitmentKey [32]byte
}

type chatOnlineEntry struct {
	context  chatOnlineContext
	deadline time.Time // monotonic: minted + TTL
}

// chatOnlineChallenges is process-local: a restart forgets every challenge.
type chatOnlineChallenges struct {
	mu      sync.Mutex
	entries map[string]chatOnlineEntry
}

func (s *chatOnlineChallenges) put(challenge string, c chatOnlineContext, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.entries == nil {
		s.entries = make(map[string]chatOnlineEntry)
	}
	for key, entry := range s.entries {
		if !now.Before(entry.deadline) {
			delete(s.entries, key)
		}
	}
	if _, exists := s.entries[challenge]; exists || len(s.entries) >= chatOnlineMaxPending {
		return false
	}
	s.entries[challenge] = chatOnlineEntry{context: c, deadline: now.Add(chatOnlineChallengeTTL)}
	return true
}

func (s *chatOnlineChallenges) peek(challenge string, now time.Time) (chatOnlineEntry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.entries[challenge]
	if !ok {
		return chatOnlineEntry{}, false
	}
	if !now.Before(entry.deadline) {
		delete(s.entries, challenge)
		return chatOnlineEntry{}, false
	}
	return entry, true
}

// consume removes the challenge once; a second caller finds nothing.
func (s *chatOnlineChallenges) consume(challenge string, now time.Time) (chatOnlineEntry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.entries[challenge]
	if !ok {
		return chatOnlineEntry{}, false
	}
	delete(s.entries, challenge)
	return entry, now.Before(entry.deadline)
}

// chatOnlineScope is the part of a protected request the decision binds.
type chatOnlineScope struct {
	Permit struct {
		AccountID      string `json:"account_id"`
		OrgID          string `json:"org_id"`
		ConversationID string `json:"conversation_id"`
	} `json:"permit"`
	OrgID          string `json:"org_id"`
	ConversationID string `json:"conversation_id"`
}

// PrepareChatOnline mints a challenge for one protected call of the App
// (lv78 K2). It is answered before the App asks the API, so the challenge
// deadline starts before the API's check.
func (a *App) PrepareChatOnline(loginGeneration string, in proto.ChatOnlinePrepareRequest) proto.BaseResponse {
	a.requestMu.Lock()
	defer a.requestMu.Unlock()
	if !dispatch.OnlineDecisionRequired(in.Action) || in.SessionIssuedAtNanos <= 0 || !proto.ChatOnlineUUID(in.TokenID) {
		return onlineDecisionRefused()
	}
	var scope chatOnlineScope
	if err := json.Unmarshal(in.Request, &scope); err != nil ||
		!proto.ChatOnlineUUID(scope.OrgID) || !proto.ChatOnlineUUID(scope.ConversationID) ||
		scope.Permit.AccountID == "" || scope.Permit.OrgID != scope.OrgID || scope.Permit.ConversationID != scope.ConversationID {
		return onlineDecisionRefused()
	}
	binding, found, err := keychain.GetAccountBinding(a.Store)
	if err != nil || !found || binding.SignedOut || binding.Generation == 0 || binding.AccountID != scope.Permit.AccountID {
		return onlineDecisionRefused()
	}
	device, found, err := keychain.GetDeviceID(a.Store)
	if err != nil || !found || device == "" {
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
		loginGeneration: loginGeneration, action: in.Action,
		orgID: scope.OrgID, conversationID: scope.ConversationID,
	}
	copy(c.commitmentKey[:], random[32:])
	c.commitment = proto.ChatOnlineRequestCommitment(c.commitmentKey[:], in.Action, in.Request)
	challenge := base64.RawURLEncoding.EncodeToString(random[:32])
	if !a.chatOnline.put(challenge, c, a.Clock()) {
		return onlineDecisionRefused()
	}
	return proto.BaseResponse{Success: true, Data: proto.ChatOnlinePrepareResponseData{
		Challenge: challenge, RequestCommitment: c.commitment,
	}}
}

// ExecuteChatOnline runs one prepared protected call with the API's decision
// (lv78 execution phases a to c). Everything runs under requestMu; nothing
// here waits on the network.
//
// (a) The decision is checked against the challenge's context, its signature
// is verified with the pinned key version it names, and the sign-in is re-read;
// only then is the challenge consumed, so a refused decision leaves it for the
// right one until its deadline. (b) The action runs through the ordinary chat
// gate (lease, epoch, sign-in generation). (c) The challenge deadline and the
// decision's expiry are checked again before anything is returned; if either
// passed, the answer is withheld as chat_online_output_withheld, not as a
// refusal: state the action wrote is not rolled back, so the App must read it
// again.
func (a *App) ExecuteChatOnline(session, epoch, loginGeneration string, in proto.ChatOnlineExecuteRequest) proto.BaseResponse {
	a.requestMu.Lock()
	defer a.requestMu.Unlock()
	if in.Decision == nil || in.Decision.Validate() != nil || a.ServerKeyVerifier == nil {
		return onlineDecisionRefused()
	}
	decision := *in.Decision
	now := a.Clock()
	if !chatOnlineWindowHolds(decision, now) {
		return onlineDecisionRefused()
	}
	entry, found := a.chatOnline.peek(decision.Challenge, now)
	c := entry.context
	if !found || !chatOnlineBindingMatches(c, decision, in, loginGeneration) {
		return onlineDecisionRefused()
	}
	if err := a.ServerKeyVerifier.Verify(proto.ChatOnlineDecisionCanonical(decision), decision.Signature, decision.ServerKeyVersion); err != nil {
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
	consumed, ok := a.chatOnline.consume(decision.Challenge, now)
	if !ok || consumed.context != c || !chatOnlineWindowHolds(decision, now) {
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
		loginGeneration: loginGeneration, chatWork: true, onlineDecision: true}
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

// chatOnlineWindowHolds is the decision's wall-clock window: not expired, and
// issued no further ahead of this clock than the display allowance.
func chatOnlineWindowHolds(d proto.ChatOnlineDecision, now time.Time) bool {
	return d.IssuedAt <= now.Unix()+proto.DisplayDecisionClockSkewSeconds && now.Unix() < d.ExpiresAt
}

// chatOnlineBindingMatches compares every field the decision binds with what
// the challenge was minted for and with the call being executed.
func chatOnlineBindingMatches(c chatOnlineContext, d proto.ChatOnlineDecision, in proto.ChatOnlineExecuteRequest, loginGeneration string) bool {
	commitment := proto.ChatOnlineRequestCommitment(c.commitmentKey[:], in.Action, in.Request)
	return hmac.Equal([]byte(commitment), []byte(c.commitment)) &&
		hmac.Equal([]byte(d.RequestCommitment), []byte(c.commitment)) &&
		in.Action == c.action && d.Action == c.action &&
		d.AccountID == c.accountID && d.DeviceID == c.deviceID &&
		d.TokenID == c.tokenID && d.SessionIssuedAtNanos == c.sessionStartNanos &&
		d.OrgID == c.orgID && d.ConversationID == c.conversationID &&
		loginGeneration == c.loginGeneration
}

// chatOnlineAfterWork runs between the action and the final validity check;
// tests use it to stand in for a suspension there. Nil in production.
var chatOnlineAfterWork func()

func setChatOnlineAfterWorkForTesting(run func()) (restore func()) {
	previous := chatOnlineAfterWork
	chatOnlineAfterWork = run
	return func() { chatOnlineAfterWork = previous }
}
