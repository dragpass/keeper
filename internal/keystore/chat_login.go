package keystore

import (
	"errors"
	"time"

	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

const ChatSessionRequired = "chat_session_binding_required"
const ChatSessionStale = "chat_session_superseded"

func chatLoginFailure(err error) proto.BaseResponse {
	if errors.Is(err, keychain.ErrChatLoginStale) {
		return proto.BaseResponse{Error: "chat session superseded", ErrorCode: ChatSessionStale}
	}
	return proto.BaseResponse{Error: "chat session storage failed", ErrorCode: "storage_failure"}
}

func (a *App) ChatLoginStatus() proto.BaseResponse {
	a.requestMu.Lock()
	defer a.requestMu.Unlock()
	state, err := keychain.ReadChatLogin(a.Store)
	if err != nil {
		return chatLoginFailure(err)
	}
	return proto.BaseResponse{Success: true, Data: map[string]any{"generation": state.Generation, "session_binding": true, "preparation_sequence": state.PreparationSequence}}
}

func (a *App) PrepareChatLogin(id, predecessor string, after uint64) proto.BaseResponse {
	a.requestMu.Lock()
	defer a.requestMu.Unlock()
	if err := keychain.PrepareChatLogin(a.Store, id, predecessor, after); err != nil {
		return chatLoginFailure(err)
	}
	return proto.BaseResponse{Success: true, Data: map[string]any{"prepared": true}}
}

// Commit waits for admitted Keeper work before fencing it. It does not undo
// plaintext already returned, permits issued by the API, or signed API work.
func (a *App) CommitChatLogin(id, accountID, alias string) proto.BaseResponse {
	a.requestMu.Lock()
	defer a.requestMu.Unlock()
	if key, err := keychain.GetPublicKey(a.Store); err != nil || key == "" {
		return proto.BaseResponse{Error: "no active account key", ErrorCode: "not_found"}
	}
	state, changed, err := keychain.CommitChatLogin(a.Store, id, accountID, alias)
	if err != nil {
		return chatLoginFailure(err)
	}
	a.chatRuntime.mu.Lock()
	if changed {
		a.revokeLocked(ChatRuntimeRevokedPurged)
	} else if a.chatRuntime.liveLocked(a.Clock()) && a.chatRuntime.bindingGeneration != state.Generation {
		// The durable fence may have committed even though its write answered an
		// error. An idempotent retry clears only an earlier incarnation's lease.
		a.chatRuntime.clearLocked()
	}
	a.chatRuntime.mu.Unlock()
	return proto.BaseResponse{Success: true, Data: map[string]any{
		"generation": state.Generation, "previous_runtime_revoked": true,
		"previous_permits_invalidated": false, "api_inflight_invalidated": false,
	}}
}

// The generation is captured by the request, never looked up on behalf of an
// older request from the current session. All checks run inside requestMu.
func (a *App) chatLoginAdmission(generation string) (proto.BaseResponse, bool) {
	state, err := keychain.ReadChatLogin(a.Store)
	if err != nil {
		return chatLoginFailure(err), false
	}
	if state.Committing || state.Generation != generation {
		return proto.BaseResponse{Error: "confirmed chat session required", ErrorCode: ChatSessionRequired}, false
	}
	return proto.BaseResponse{}, true
}

func (a *App) ClaimChatRuntimeBound(holder, session string, remaining time.Duration, epoch, generation string, sequence uint64) (ChatRuntimeClaim, string) {
	a.requestMu.Lock()
	defer a.requestMu.Unlock()
	if refusal, ok := a.chatLoginAdmission(generation); !ok {
		return ChatRuntimeClaim{}, refusal.ErrorCode
	}
	if err := keychain.ConsumeChatClaim(a.Store, generation, holder, sequence); err != nil {
		if errors.Is(err, keychain.ErrChatLoginStale) {
			return ChatRuntimeClaim{}, "chat_runtime_claim_stale"
		}
		return ChatRuntimeClaim{}, "storage_failure"
	}
	claim := a.ClaimChatRuntime(holder, session, remaining, epoch)
	if claim.Granted {
		a.chatRuntime.mu.Lock()
		a.chatRuntime.bindingGeneration = generation
		a.chatRuntime.mu.Unlock()
	}
	return claim, ""
}

func (a *App) HandleAppFencedRequest(session, epoch, generation string, chatWork bool, msg []byte) proto.BaseResponse {
	return a.handleAs(chatRuntimeCaller{app: true, session: session, epoch: epoch,
		loginGeneration: generation, chatWork: chatWork}, msg)
}

// Kept separate from the ordinary dispatch entry point for signing routes.
func (a *App) HandleAppFencedChatWrite(session, epoch, generation string, msg []byte) proto.BaseResponse {
	return a.handleAs(chatRuntimeCaller{app: true, session: session, epoch: epoch,
		loginGeneration: generation, chatWrite: true, chatWork: true}, msg)
}
