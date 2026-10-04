// chat_runtime.go — the chat runtime lease: one caller drives chat at a time.
//
// The App (local RPC) and the Extension (Native Messaging, stdio or proxied)
// share this process and its per-conversation state locks, but each runs its
// own chat orchestration: outbox, pending Commit retry, reconciliation. Two
// orchestrators on one device would each take the other's pending Commit for
// a lost answer. The lease makes the choice explicit and process-local:
//
//   - The App claims it for a holder id (one App tab) bound to its local RPC
//     session. Only that session may run a gated action while it holds it.
//   - While a live App lease exists, every gated action from the Extension is
//     refused with chat_runtime_busy before its handler runs. An Extension
//     that does not know the code fails closed rather than splitting state.
//   - A gated action the Extension ran stamps activity; for
//     ChatRuntimeExtensionWindow after it the App cannot claim.
//
// Admission and the stamp happen under one mutex, so a claim and an Extension
// gated call racing at the same instant never both succeed. The mutex is its
// own, not requestMu: a claim must not wait behind a long MLS action.
//
// A revocation (chat_state_purge, reset_device_identity) wins over a live App
// lease: the Extension's is never refused busy, and any caller's moves the
// lease epoch and drops the lease. The App presents the epoch it was granted
// on every gated call, so work it still has in flight after a logout or reset
// is refused with chat_runtime_revoked instead of landing on the erased state.
// The gate runs inside requestMu, the lock every handler runs under, so the
// epoch check and the handler's write are one step with respect to the
// revocation: an App handler already admitted finishes before the purge runs,
// and none is admitted after it.

package keystore

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/dragpass/keeper/config"

	"github.com/dragpass/keeper/internal/keystore/dispatch"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

const (
	ChatRuntimeLeaseTTL        = 60 * time.Second
	ChatRuntimeExtensionWindow = 120 * time.Second

	ErrCodeChatRuntimeBusy          = "chat_runtime_busy"
	ErrCodeChatRuntimeLeaseRequired = "chat_runtime_lease_required"
	ErrCodeChatRuntimeRevoked       = "chat_runtime_revoked"

	ChatRuntimeRevokedPurged = "purged"
	ChatRuntimeRevokedReset  = "reset"

	ChatRuntimeHolderApp       = "app"
	ChatRuntimeHolderExtension = "extension"
)

// chatRuntimeGated lists every action that writes chat state, MLS group
// state, leaf slots or the KeyPackage pool, plus the display decrypt (which
// advances the receive state). Read-only reports and signed statements are
// not here: either caller may run them at any time.
var chatRuntimeGated = map[string]struct{}{
	proto.MLSGroupCreate:               {},
	proto.MLSGroupDiscardUnaccepted:    {},
	proto.MLSConversationForgetRemoved: {},
	proto.MLSCommitBuild:               {},
	proto.MLSCommitConfirm:             {},
	proto.MLSProcess:                   {},
	proto.MLSJoin:                      {},
	proto.MLSEncrypt:                   {},
	proto.MLSMarkSent:                  {},
	proto.MLSDecryptBatchForAppDisplay: {},
	proto.MLSCommitAbandon:             {},
	proto.ChatStateReadOutbox:          {},
	proto.ChatStatePurge:               {},
	proto.ActionMLSLeafDeclare:         {},
	proto.ActionMLSLeafPromote:         {},
	proto.ActionMLSLeafAbort:           {},
	proto.MLSKeyPackageGenerate:        {},
	proto.MLSKeyPackagePoolSweep:       {},
	proto.ActionResetDeviceIdentity:    {},
}

// chatRuntimeRevocations are the gated actions that erase chat state. They
// move the epoch for any caller and are never refused busy to the Extension.
var chatRuntimeRevocations = map[string]string{
	proto.ChatStatePurge:            ChatRuntimeRevokedPurged,
	proto.ActionResetDeviceIdentity: ChatRuntimeRevokedReset,
}

// ChatRuntimeGatedActions returns the gated action names, sorted.
func ChatRuntimeGatedActions() []string {
	out := make([]string, 0, len(chatRuntimeGated))
	for action := range chatRuntimeGated {
		out = append(out, action)
	}
	sort.Strings(out)
	return out
}

type chatRuntimeLease struct {
	mu          sync.Mutex
	holder      string
	session     string
	expires     time.Time
	extensionAt time.Time
	// epoch is loaded from the store on first use and moved by revocations.
	epoch       chatRuntimeEpoch
	epochLoaded bool
}

// chatRuntimeEpoch is persisted so a restart can neither reuse an old value
// nor move it: only a revocation does. ID is random and made when the record
// is first written, so a lost record never re-issues an earlier epoch.
type chatRuntimeEpoch struct {
	ID         string `json:"id"`
	Generation uint64 `json:"generation"`
	Reason     string `json:"reason,omitempty"`
}

func (e chatRuntimeEpoch) token() string {
	return e.ID + "." + strconv.FormatUint(e.Generation, 10)
}

// chatRuntimeEpochAccount is a Keychain slot reset_device_identity does not
// clear: the epoch has to outlive the state it fences.
const chatRuntimeEpochAccount = "chat-runtime-epoch"

func newChatRuntimeEpochID() string {
	raw := make([]byte, 16)
	_, _ = rand.Read(raw)
	return base64.RawURLEncoding.EncodeToString(raw)
}

// currentEpochLocked loads the epoch record, creating it when missing or
// unreadable. A fresh record revokes every earlier epoch, which fails closed.
// A failed write keeps the in-memory value; the next revocation tries again.
func (a *App) currentEpochLocked() chatRuntimeEpoch {
	l := &a.chatRuntime
	if l.epochLoaded {
		return l.epoch
	}
	l.epochLoaded = true
	if raw, err := a.Store.Get(config.Service, chatRuntimeEpochAccount); err == nil {
		var stored chatRuntimeEpoch
		if json.Unmarshal([]byte(raw), &stored) == nil && stored.ID != "" {
			l.epoch = stored
			return l.epoch
		}
	}
	l.epoch = chatRuntimeEpoch{ID: newChatRuntimeEpochID()}
	a.persistEpochLocked()
	return l.epoch
}

func (a *App) persistEpochLocked() {
	raw, _ := json.Marshal(a.chatRuntime.epoch)
	if err := a.Store.Set(config.Service, chatRuntimeEpochAccount, string(raw)); err != nil {
		a.Logger.Printf("chat runtime epoch could not be persisted: %v", err)
	}
}

// revokeLocked moves the epoch and drops the lease. It runs at admission,
// before the erasing handler, so a restart after the erasure cannot hand the
// old epoch back.
func (a *App) revokeLocked(reason string) {
	l := &a.chatRuntime
	current := a.currentEpochLocked()
	l.epoch = chatRuntimeEpoch{ID: current.ID, Generation: current.Generation + 1, Reason: reason}
	a.persistEpochLocked()
	l.clearLocked()
}

// revokedReasonLocked is why the current epoch replaced the caller's. A
// record from before reasons were kept says purged, the milder of the two.
func (a *App) revokedReasonLocked() string {
	if reason := a.chatRuntime.epoch.Reason; reason != "" {
		return reason
	}
	return ChatRuntimeRevokedPurged
}

// ChatRuntimeRevokedResponse is the refusal for a stale epoch. The App stops
// that runtime and never retries its work.
func ChatRuntimeRevokedResponse(reason string) proto.BaseResponse {
	return proto.BaseResponse{
		Error:     "chat was reset on this device; this chat runtime is no longer valid",
		ErrorCode: ErrCodeChatRuntimeRevoked,
		Data:      map[string]string{"reason": reason},
	}
}

func (l *chatRuntimeLease) liveLocked(now time.Time) bool {
	return l.holder != "" && now.Before(l.expires)
}

func (l *chatRuntimeLease) clearLocked() {
	l.holder, l.session, l.expires = "", "", time.Time{}
}

// ChatRuntimeClaim is the outcome of a claim. When Granted is false,
// BusyHolder names who is in the way, or Revoked says the epoch the caller
// held was revoked and why.
type ChatRuntimeClaim struct {
	Granted    bool
	ExpiresAt  time.Time
	Epoch      string
	BusyHolder string
	Revoked    string
}

// ClaimChatRuntime grants, renews or rebinds the lease for holderID on
// session. The lease never outlives the session: sessionRemaining is how long
// the session has left by its own clock. heldEpoch is the epoch a running
// runtime already holds ("" for a new one); a stale one is refused, so a
// runtime that lived through a revocation cannot re-claim its way back.
func (a *App) ClaimChatRuntime(holderID, session string, sessionRemaining time.Duration, heldEpoch string) ChatRuntimeClaim {
	l := &a.chatRuntime
	l.mu.Lock()
	defer l.mu.Unlock()
	now := a.Clock()
	epoch := a.currentEpochLocked()
	if heldEpoch != "" && heldEpoch != epoch.token() {
		return ChatRuntimeClaim{Revoked: a.revokedReasonLocked()}
	}
	live := l.liveLocked(now)
	switch {
	case live && l.holder != holderID:
		return ChatRuntimeClaim{BusyHolder: ChatRuntimeHolderApp}
	case !live && !l.extensionAt.IsZero() && now.Sub(l.extensionAt) < ChatRuntimeExtensionWindow:
		return ChatRuntimeClaim{BusyHolder: ChatRuntimeHolderExtension}
	}
	expires := now.Add(min(ChatRuntimeLeaseTTL, sessionRemaining))
	l.holder, l.session, l.expires = holderID, session, expires
	return ChatRuntimeClaim{Granted: true, ExpiresAt: expires, Epoch: epoch.token()}
}

// ReleaseChatRuntime drops a live lease held by holderID.
func (a *App) ReleaseChatRuntime(holderID string) bool {
	l := &a.chatRuntime
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.liveLocked(a.Clock()) || l.holder != holderID {
		return false
	}
	l.clearLocked()
	return true
}

// DropChatRuntimeSession drops the lease bound to a local RPC session that was
// closed or expired.
func (a *App) DropChatRuntimeSession(session string) {
	l := &a.chatRuntime
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.holder != "" && l.session == session {
		l.clearLocked()
	}
}

// DropAllChatRuntimeSessions drops the lease when every local RPC session
// went at once (the local secret was rotated).
func (a *App) DropAllChatRuntimeSessions() {
	l := &a.chatRuntime
	l.mu.Lock()
	defer l.mu.Unlock()
	l.clearLocked()
}

// chatRuntimeCaller is who framed a request: the Extension (no session) or
// the App bound to one local RPC session, presenting the epoch it was
// granted. chatWrite gates an otherwise ungated action: the signature of a
// chat write the App is about to send to the server.
type chatRuntimeCaller struct {
	app       bool
	session   string
	epoch     string
	chatWrite bool
}

func leaseRequired() proto.BaseResponse {
	return proto.BaseResponse{
		Error:     "this App session does not hold the chat runtime lease",
		ErrorCode: ErrCodeChatRuntimeLeaseRequired,
	}
}

func (a *App) chatRuntimeGate(caller chatRuntimeCaller) dispatch.Gate {
	return func(action string) (proto.BaseResponse, bool) {
		if _, gated := chatRuntimeGated[action]; !gated && !caller.chatWrite {
			return proto.BaseResponse{}, true
		}
		l := &a.chatRuntime
		l.mu.Lock()
		defer l.mu.Unlock()
		now := a.Clock()
		live := l.liveLocked(now)
		revocation, revokes := chatRuntimeRevocations[action]
		if caller.app {
			if caller.epoch == "" {
				return leaseRequired(), false
			}
			if caller.epoch != a.currentEpochLocked().token() {
				return ChatRuntimeRevokedResponse(a.revokedReasonLocked()), false
			}
			if !live || caller.session == "" || l.session != caller.session {
				return leaseRequired(), false
			}
			if revokes {
				a.revokeLocked(revocation)
			}
			return proto.BaseResponse{}, true
		}
		if revokes {
			a.revokeLocked(revocation)
			l.extensionAt = now
			return proto.BaseResponse{}, true
		}
		if live {
			return proto.BaseResponse{
				Error:     "the DragPass app is running chat on this device",
				ErrorCode: ErrCodeChatRuntimeBusy,
				Data:      map[string]string{"holder": ChatRuntimeHolderApp},
			}, false
		}
		l.extensionAt = now
		return proto.BaseResponse{}, true
	}
}
