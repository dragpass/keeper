// Dispatch (HandleRequest + Messenger bindings) aliases.
//
// dispatcher.go / messaging.go / utils.go (process[T]) live in the
// internal/keystore/dispatch/ subpackage. dispatch does not import keystore
// root (to avoid cycles); App.HandleRequest is a thin wrapper that injects
// logger / handlers.Deps into dispatch explicitly.
//
// The free HandleRequest / NewMessenger compatibility wrappers that
// implicitly bound to the process-wide DefaultApp() have been removed.
// Production main and facade tests both inject dispatcher dependencies
// from an explicit *App instance.

package keystore

import (
	"io"

	"github.com/dragpass/keeper/internal/keystore/dispatch"
	"github.com/dragpass/keeper/internal/keystore/handlers"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// HandleRequest processes incoming requests using the BaseRequest envelope pattern.
// The request's RequestID is echoed verbatim in the response and used by
// the Extension for multiplexing. If the RequestID can't be read (e.g.
// JSON parse failure), the empty string goes out.
//
// This method is a thin wrapper that delegates to dispatch.HandleRequest,
// injecting app.Logger and app.HandlersDeps() explicitly.
func (a *App) HandleRequest(msg []byte) proto.BaseResponse {
	return dispatch.HandleRequest(a.Logger, a.HandlersDeps(), msg)
}

// HandlersDeps converts App fields to handlers.Deps for handler invocation.
// The dispatcher wraps *App fields just before handler invocation to
// cross the package boundary.
func (a *App) HandlersDeps() handlers.Deps {
	return handlers.Deps{
		Logger:            a.Logger,
		Store:             a.Store,
		Clock:             a.Clock,
		Rand:              a.Rand,
		ServerKeyVerifier: a.ServerKeyVerifier,
		GroupSessions:     a.GroupSessions,
		RecoverySessions:  a.RecoverySessions,
		Clipboard:         a.Clipboard,
		UserPresence:      a.UserPresence,
	}
}

// NewMessenger binds native messaging to this App's logger. main.go keeps its
// dependency graph explicit by calling app.NewMessenger(...).
func (a *App) NewMessenger(in io.Reader, out io.Writer) *dispatch.Messenger {
	return dispatch.NewMessenger(in, out, a.Logger)
}
