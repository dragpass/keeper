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

package keystore

import (
	"sort"
	"sync"
	"time"

	"github.com/dragpass/keeper/internal/keystore/dispatch"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

const (
	ChatRuntimeLeaseTTL        = 60 * time.Second
	ChatRuntimeExtensionWindow = 120 * time.Second

	ErrCodeChatRuntimeBusy          = "chat_runtime_busy"
	ErrCodeChatRuntimeLeaseRequired = "chat_runtime_lease_required"

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
	proto.ChatStateReserveSend:         {},
	proto.ChatStateCommitOutbox:        {},
	proto.ChatStateReadOutbox:          {},
	proto.ChatStateMarkReceived:        {},
	proto.ChatStatePurge:               {},
	proto.ActionMLSLeafDeclare:         {},
	proto.ActionMLSLeafPromote:         {},
	proto.ActionMLSLeafAbort:           {},
	proto.MLSKeyPackageGenerate:        {},
	proto.MLSKeyPackagePoolSweep:       {},
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
}

func (l *chatRuntimeLease) liveLocked(now time.Time) bool {
	return l.holder != "" && now.Before(l.expires)
}

func (l *chatRuntimeLease) clearLocked() {
	l.holder, l.session, l.expires = "", "", time.Time{}
}

// ChatRuntimeClaim is the outcome of a claim. BusyHolder names who is in the
// way when Granted is false.
type ChatRuntimeClaim struct {
	Granted    bool
	ExpiresAt  time.Time
	BusyHolder string
}

// ClaimChatRuntime grants, renews or rebinds the lease for holderID on
// session. The lease never outlives the session: sessionRemaining is how long
// the session has left by its own clock.
func (a *App) ClaimChatRuntime(holderID, session string, sessionRemaining time.Duration) ChatRuntimeClaim {
	l := &a.chatRuntime
	l.mu.Lock()
	defer l.mu.Unlock()
	now := a.Clock()
	live := l.liveLocked(now)
	switch {
	case live && l.holder != holderID:
		return ChatRuntimeClaim{BusyHolder: ChatRuntimeHolderApp}
	case !live && !l.extensionAt.IsZero() && now.Sub(l.extensionAt) < ChatRuntimeExtensionWindow:
		return ChatRuntimeClaim{BusyHolder: ChatRuntimeHolderExtension}
	}
	expires := now.Add(min(ChatRuntimeLeaseTTL, sessionRemaining))
	l.holder, l.session, l.expires = holderID, session, expires
	return ChatRuntimeClaim{Granted: true, ExpiresAt: expires}
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
// the App bound to one local RPC session.
type chatRuntimeCaller struct {
	app     bool
	session string
}

func (a *App) chatRuntimeGate(caller chatRuntimeCaller) dispatch.Gate {
	return func(action string) (proto.BaseResponse, bool) {
		if _, gated := chatRuntimeGated[action]; !gated {
			return proto.BaseResponse{}, true
		}
		l := &a.chatRuntime
		l.mu.Lock()
		defer l.mu.Unlock()
		now := a.Clock()
		live := l.liveLocked(now)
		if caller.app {
			if live && caller.session != "" && l.session == caller.session {
				return proto.BaseResponse{}, true
			}
			return proto.BaseResponse{
				Error:     "this App session does not hold the chat runtime lease",
				ErrorCode: ErrCodeChatRuntimeLeaseRequired,
			}, false
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
