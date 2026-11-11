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
		proto.MLSGroupCreate:               direct(handlers.HandleMLSGroupCreate).gated().needsOnlineDecision(),
		proto.MLSGroupDiscardUnaccepted:    direct(handlers.HandleMLSGroupDiscardUnaccepted).gated(),
		proto.MLSConversationForgetRemoved: direct(handlers.HandleMLSConversationForgetRemoved).gated(),
		proto.MLSCommitBuild:               direct(handlers.HandleMLSCommitBuild).gated().needsOnlineDecision(),
		proto.MLSCommitConfirm:             direct(handlers.HandleMLSCommitConfirm).gated().needsOnlineDecision(),
		proto.MLSProcess:                   direct(handlers.HandleMLSProcess).gated().needsOnlineDecision(),
		proto.MLSJoin:                      direct(handlers.HandleMLSJoin).gated().needsOnlineDecision(),
		proto.MLSEncrypt:                   direct(handlers.HandleMLSEncrypt).gated().needsOnlineDecision(),
		proto.MLSMarkSent:                  direct(handlers.HandleMLSMarkSent).gated().needsOnlineDecision(),
		proto.MLSDecryptBatchForAppDisplay: direct(handlers.HandleMLSDecryptBatchForAppDisplay).gated().returnsPlaintext().needsOnlineDecision(),
		proto.MLSRoomNameSeal:              direct(handlers.HandleMLSRoomNameSeal).chatFree().appOnlyAction().needsOnlineDecision(),
		proto.MLSRoomNameOpen:              direct(handlers.HandleMLSRoomNameOpen).chatFree().appOnlyAction().returnsPlaintext().needsOnlineDecision(),
		proto.MLSConversationStatus:        direct(handlers.HandleMLSConversationStatus).chatFree().appOnlyAction().needsOnlineDecision(),
		proto.MLSEpochComparison:           direct(handlers.HandleMLSEpochComparison).chatFree().appOnlyAction().needsOnlineDecision(),
		proto.MLSRejoinRequestSign:         direct(handlers.HandleMLSRejoinRequestSign).chatFree().appOnlyAction().needsOnlineDecision(),
		proto.MLSLeaveRequestSign:          direct(handlers.HandleMLSLeaveRequestSign).chatFree().appOnlyAction().needsOnlineDecision(),
		proto.OrgMemberRemovalSign:         wrap(handlers.HandleOrgMemberRemovalSign).chatFree(),
		proto.MLSDeviceRevokeSign:          wrap(handlers.HandleMLSDeviceRevokeSign).chatFree().appOnlyAction(),
	}
}
