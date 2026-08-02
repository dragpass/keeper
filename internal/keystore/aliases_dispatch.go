package keystore

import (
	"io"

	"github.com/dragpass/keeper/internal/keystore/dispatch"
	"github.com/dragpass/keeper/internal/keystore/handlers"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// HandleRequest dispatches one native messaging request.
func (a *App) HandleRequest(msg []byte) proto.BaseResponse {
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
		UserPresence:        a.UserPresence,
	}
}

func (a *App) NewMessenger(in io.Reader, out io.Writer) *dispatch.Messenger {
	return dispatch.NewMessenger(in, out, a.Logger)
}
