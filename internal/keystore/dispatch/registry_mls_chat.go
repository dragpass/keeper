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

// Chat runs only in the App. The ungated reads and statements are App-only
// too, except org_member_removal_sign, which the Extension's E2E member
// fixture signs over Native Messaging.
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
		proto.MLSRoomNameSeal:              direct(handlers.HandleMLSRoomNameSeal).chatFree().appOnlyAction(),
		proto.MLSRoomNameOpen:              direct(handlers.HandleMLSRoomNameOpen).chatFree().appOnlyAction().returnsPlaintext(),
		proto.MLSConversationStatus:        direct(handlers.HandleMLSConversationStatus).chatFree().appOnlyAction(),
		proto.MLSEpochComparison:           direct(handlers.HandleMLSEpochComparison).chatFree().appOnlyAction(),
		proto.MLSRejoinRequestSign:         direct(handlers.HandleMLSRejoinRequestSign).chatFree().appOnlyAction(),
		proto.MLSLeaveRequestSign:          direct(handlers.HandleMLSLeaveRequestSign).chatFree().appOnlyAction(),
		proto.OrgMemberRemovalSign:         wrap(handlers.HandleOrgMemberRemovalSign).chatFree(),
		proto.MLSDeviceRevokeSign:          wrap(handlers.HandleMLSDeviceRevokeSign).chatFree().appOnlyAction(),
	}
}
