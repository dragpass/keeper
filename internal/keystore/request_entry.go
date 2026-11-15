package keystore

import (
	"encoding/json"
	"io"

	"github.com/dragpass/keeper/internal/keystore/dispatch"
	"github.com/dragpass/keeper/internal/keystore/handlers"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// HandleRequest dispatches one native messaging request. Requests run one at
// a time: the handlers were written for the serial Native Messaging loop, and
// a local RPC owner now takes requests from its stdio, the App and proxied
// hosts at once.
//
// HandleRequest is the Extension's entry: its stdio loop and the frames other
// Native Messaging hosts proxy here. HandleAppRequest is the App's, bound to
// its local RPC session. The chat runtime lease (chat_runtime.go) tells them
// apart; the lease check runs inside requestMu, next to the handler it admits.
func (a *App) HandleRequest(msg []byte) proto.BaseResponse {
	if refused, ok := nativeOrgArchiveGenerate(msg); ok {
		return refused
	}
	return a.handleAs(chatRuntimeCaller{}, msg)
}

// nativeOrgArchiveGenerate refuses an archive_key_generate frame that names an
// org on Native Messaging (lv96). The org-scoped form belongs to the App's
// organization console; the Extension's device-wide call (its E2E org
// fixture) sends no org_id and is unchanged. A Keeper before lv96 ignored the
// field on this path and generated the device-wide key.
func nativeOrgArchiveGenerate(msg []byte) (proto.BaseResponse, bool) {
	var frame proto.BaseRequest
	if json.Unmarshal(msg, &frame) != nil || frame.Action != proto.ActionArchiveKeyGenerate || len(frame.Payload) == 0 {
		return proto.BaseResponse{}, false
	}
	var payload struct {
		OrgID *string `json:"org_id"`
	}
	if json.Unmarshal(frame.Payload, &payload) != nil || payload.OrgID == nil {
		return proto.BaseResponse{}, false
	}
	refused := appCallerRequired()
	refused.RequestID = frame.RequestID
	return refused, true
}

// HandleAppRequest runs one App request; epoch is the chat runtime epoch the
// App was granted ("" when it holds none).
func (a *App) HandleAppRequest(session, epoch string, msg []byte) proto.BaseResponse {
	return a.handleAs(chatRuntimeCaller{app: true, session: session, epoch: epoch}, msg)
}

// HandleAppChatWrite runs msg only for the session holding a live lease at
// the current epoch, whatever the action: it signs a chat write the App is
// about to send to the server, so a revoked runtime cannot post one.
func (a *App) HandleAppChatWrite(session, epoch string, msg []byte) proto.BaseResponse {
	return a.handleAs(chatRuntimeCaller{app: true, session: session, epoch: epoch, chatWrite: true}, msg)
}

// HandleAppSteps runs a flow Keeper composes for the App from several actions
// under one hold of requestMu, so no Native Messaging, proxied or other App
// request lands between its steps. run dispatches one action message as the
// App caller and is valid only until steps returns; steps must not call any
// other App entry point, which would wait on the lock it holds.
func (a *App) HandleAppSteps(
	session, epoch string,
	steps func(run func(msg []byte) proto.BaseResponse) (proto.BaseResponse, error),
) (proto.BaseResponse, error) {
	a.requestMu.Lock()
	defer a.requestMu.Unlock()
	caller := chatRuntimeCaller{app: true, session: session, epoch: epoch}
	return steps(func(msg []byte) proto.BaseResponse {
		return dispatch.HandleRequestGatedAfter(a.Logger, a.HandlersDeps(), msg, a.chatRuntimeGate(caller), a.chatRuntimeAfter(caller))
	})
}

// HandleAppFencedSteps carries the same captured generation through a composed chat route.
func (a *App) HandleAppFencedSteps(session, epoch, generation string,
	steps func(run func(msg []byte) proto.BaseResponse) (proto.BaseResponse, error),
) (proto.BaseResponse, error) {
	a.requestMu.Lock()
	defer a.requestMu.Unlock()
	caller := chatRuntimeCaller{app: true, session: session, epoch: epoch, loginGeneration: generation, chatWork: true}
	return steps(func(msg []byte) proto.BaseResponse {
		return dispatch.HandleRequestGatedAfter(a.Logger, a.HandlersDeps(), msg, a.chatRuntimeGate(caller), a.chatRuntimeAfter(caller))
	})
}

func (a *App) handleAs(caller chatRuntimeCaller, msg []byte) proto.BaseResponse {
	a.requestMu.Lock()
	defer a.requestMu.Unlock()
	return dispatch.HandleRequestGatedAfter(a.Logger, a.HandlersDeps(), msg, a.chatRuntimeGate(caller), a.chatRuntimeAfter(caller))
}

func (a *App) HandlersDeps() handlers.Deps {
	return handlers.Deps{
		Logger:                   a.Logger,
		Store:                    a.Store,
		Clock:                    a.Clock,
		Rand:                     a.Rand,
		ServerKeyVerifier:        a.ServerKeyVerifier,
		GroupSessions:            a.GroupSessions,
		RecoverySessions:         a.RecoverySessions,
		RecoveryKeySessions:      a.RecoveryKeySessions,
		Clipboard:                a.Clipboard,
		MessageChallenges:        a.MessageChallenges,
		GroupDisplayChallenges:   a.GroupDisplayChallenges,
		GroupRewrapChallenges:    a.GroupRewrapChallenges,
		ArchiveShareChallenges:   a.ArchiveShareChallenges,
		ArchiveSplitChallenges:   a.ArchiveSplitChallenges,
		ArchiveProofChallenges:   a.ArchiveProofChallenges,
		ChangeBaselineChallenges: a.ChangeBaselineChallenges,
		ChangeCompareChallenges:  a.ChangeCompareChallenges,
		AuditAuthorizations:      a.AuditAuthorizations,
		CredentialNonces:         a.CredentialNonces,
		KeyTransparency:          a.KeyTransparency,
	}
}

func (a *App) VerifyKeyTransparencyAccountEvents(request proto.KeyTransparencyMonitorRequest) proto.BaseResponse {
	a.requestMu.Lock()
	defer a.requestMu.Unlock()
	return handlers.HandleKeyTransparencyMonitor(a.HandlersDeps(), request)
}

func (a *App) NewMessenger(in io.Reader, out io.Writer) *dispatch.Messenger {
	return dispatch.NewMessenger(in, out, a.Logger)
}
