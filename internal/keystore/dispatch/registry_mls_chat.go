// registry_mls_chat.go — DragPass chat MLS action registrations.
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

func mlsChatActions() map[string]action {
	return map[string]action{
		proto.MLSGroupCreate:               direct(handlers.HandleMLSGroupCreate).gated(),
		proto.MLSGroupDiscardUnaccepted:    direct(handlers.HandleMLSGroupDiscardUnaccepted).gated(),
		proto.MLSConversationForgetRemoved: direct(handlers.HandleMLSConversationForgetRemoved).gated(),
		proto.MLSCommitBuild:               direct(handlers.HandleMLSCommitBuild).gated(),
		proto.MLSCommitConfirm:             direct(handlers.HandleMLSCommitConfirm).gated(),
		proto.MLSProcess:                   direct(handlers.HandleMLSProcess).gated(),
		proto.MLSJoin:                      direct(handlers.HandleMLSJoin).gated(),
		proto.MLSEncrypt:                   direct(handlers.HandleMLSEncrypt).gated(),
		proto.MLSMarkSent:                  direct(handlers.HandleMLSMarkSent).gated(),
		proto.MLSDecryptBatchForAppDisplay: direct(handlers.HandleMLSDecryptBatchForAppDisplay).gated().returnsPlaintext(),
		proto.MLSRoomNameSeal:              direct(handlers.HandleMLSRoomNameSeal).chatFree(),
		proto.MLSRoomNameOpen:              direct(handlers.HandleMLSRoomNameOpen).chatFree().returnsPlaintext(),
		proto.MLSConversationStatus:        direct(handlers.HandleMLSConversationStatus).chatFree(),
		proto.MLSEpochComparison:           direct(handlers.HandleMLSEpochComparison).chatFree(),
		proto.MLSRejoinRequestSign:         direct(handlers.HandleMLSRejoinRequestSign).chatFree(),
		proto.MLSLeaveRequestSign:          direct(handlers.HandleMLSLeaveRequestSign).chatFree(),
		proto.OrgMemberRemovalSign:         wrap(handlers.HandleOrgMemberRemovalSign).chatFree(),
		proto.MLSDeviceRevokeSign:          wrap(handlers.HandleMLSDeviceRevokeSign).chatFree(),
	}
}
