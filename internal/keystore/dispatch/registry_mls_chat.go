// registry_mls_chat.go — DragPass chat v2 MLS action registrations.
//
// Mirrors proto/actions_mls_chat.go. Its own fragment because these are the
// only actions that read and write the MLS group state inside the chat state
// record. They register handlers directly for the reason
// registry_chat_state.go gives: every request is bound into a server-signed
// permit and needs the strict decoder, which each handler runs itself.

package dispatch

import (
	"github.com/dragpass/keeper/internal/keystore/handlers"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

func mlsChatActions() map[string]actionHandlerFunc {
	return map[string]actionHandlerFunc{
		proto.MLSGroupCreate:               handlers.HandleMLSGroupCreate,
		proto.MLSGroupDiscardUnaccepted:    handlers.HandleMLSGroupDiscardUnaccepted,
		proto.MLSConversationForgetRemoved: handlers.HandleMLSConversationForgetRemoved,
		proto.MLSCommitBuild:               handlers.HandleMLSCommitBuild,
		proto.MLSCommitConfirm:             handlers.HandleMLSCommitConfirm,
		proto.MLSProcess:                   handlers.HandleMLSProcess,
		proto.MLSJoin:                      handlers.HandleMLSJoin,
		proto.MLSEncrypt:                   handlers.HandleMLSEncrypt,
		proto.MLSMarkSent:                  handlers.HandleMLSMarkSent,
		proto.MLSDecryptBatchForAppDisplay: handlers.HandleMLSDecryptBatchForAppDisplay,
		proto.MLSRoomNameSeal:              handlers.HandleMLSRoomNameSeal,
		proto.MLSRoomNameOpen:              handlers.HandleMLSRoomNameOpen,
		proto.MLSConversationStatus:        handlers.HandleMLSConversationStatus,
	}
}
