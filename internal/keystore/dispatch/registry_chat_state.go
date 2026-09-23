// registry_chat_state.go — DragPass chat v2 conversation-state registrations.
//
// Mirrors proto/actions_chat_state.go. Its own fragment because these five are
// their own security domain: the only actions that read or write conversation
// state, and the only ones gated on a conversation-state permit.
//
// Like registry_conversation.go they register handlers directly rather than
// through wrap(). wrap() routes through `process`, which decodes with plain
// json.Unmarshal; these requests are bound into a server signature, so they
// need a decoder that refuses duplicate keys, unknown fields, and missing
// fields, and they own that decode themselves. See handlers/strict_json.go.

package dispatch

import (
	"github.com/dragpass/keeper/internal/keystore/handlers"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

func chatStateActions() map[string]actionHandlerFunc {
	return map[string]actionHandlerFunc{
		proto.ChatStateReserveSend:  handlers.HandleChatStateReserveSend,
		proto.ChatStateCommitOutbox: handlers.HandleChatStateCommitOutbox,
		proto.ChatStateReadOutbox:   handlers.HandleChatStateReadOutbox,
		proto.ChatStateMarkReceived: handlers.HandleChatStateMarkReceived,
		proto.ChatStatePurge:        handlers.HandleChatStatePurge,
	}
}
