package keystore

import (
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
	return a.handleAs(chatRuntimeCaller{}, msg)
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
		return dispatch.HandleRequestGated(a.Logger, a.HandlersDeps(), msg, a.chatRuntimeGate(caller))
	})
}

func (a *App) handleAs(caller chatRuntimeCaller, msg []byte) proto.BaseResponse {
	a.requestMu.Lock()
	defer a.requestMu.Unlock()
	return dispatch.HandleRequestGated(a.Logger, a.HandlersDeps(), msg, a.chatRuntimeGate(caller))
}

func (a *App) HandlersDeps() handlers.Deps {
	return handlers.Deps{
		Logger:              a.Logger,
		Store:               a.Store,
		Clock:               a.Clock,
		Rand:                a.Rand,
		ServerKeyVerifier:   a.ServerKeyVerifier,
		GroupSessions:       a.GroupSessions,
		RecoverySessions:    a.RecoverySessions,
		RecoveryKeySessions: a.RecoveryKeySessions,
		Clipboard:           a.Clipboard,
		MessageChallenges:   a.MessageChallenges,
		KeyTransparency:     a.KeyTransparency,
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
