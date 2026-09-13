// registry_conversation.go — DragPass 1:1 chat reveal action registration.
//
// Mirrors proto/actions_conversation.go. This action is its own security
// domain — a server-signed conversation-read-permit and a plaintext-returning
// response — so it keeps its own registry fragment rather than riding on the
// Group DEK catalog.
//
// Like registry_message.go it registers the handler directly instead of through
// wrap(). wrap() routes through `process`, which decodes with plain
// json.Unmarshal; this request is bound into a server signature, so it needs a
// decoder that refuses duplicate keys, unknown fields, and missing fields, and
// it owns that decode itself. See handlers/strict_json.go and
// handlers/conversation_decrypt.go.

package dispatch

import (
	"github.com/dragpass/keeper/internal/keystore/handlers"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

func conversationActions() map[string]actionHandlerFunc {
	return map[string]actionHandlerFunc{
		proto.ActionConversationDecryptBatchForAppDisplay: handlers.HandleConversationDecryptBatchForAppDisplay,
	}
}
