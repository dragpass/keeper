// registry_chat_state.go — DragPass chat conversation-state registrations.
//
// Mirrors proto/actions_chat_state.go. Its own fragment because these are
// their own security domain: outside the MLS actions, the only ones that read
// or write conversation state.
//
// Like registry_message.go they register handlers directly rather than
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
		proto.ChatStateReadOutbox: handlers.HandleChatStateReadOutbox,
		proto.ChatStatePurge:      handlers.HandleChatStatePurge,
	}
}
