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
func (a *App) HandleRequest(msg []byte) proto.BaseResponse {
	a.requestMu.Lock()
	defer a.requestMu.Unlock()
	return dispatch.HandleRequest(a.Logger, a.HandlersDeps(), msg)
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

func (a *App) NewMessenger(in io.Reader, out io.Writer) *dispatch.Messenger {
	return dispatch.NewMessenger(in, out, a.Logger)
}
