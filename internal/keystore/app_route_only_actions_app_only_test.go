package keystore

import (
	"encoding/json"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/proto"
)

// appRouteOnlyActions are called only by the App's Local RPC routes: the
// account binding, account key rotation, password and session-code steps of
// the App's sign-in, the recovery handle close and old-key rewrap, the org
// and account archive key, break-glass and quorum surface, the chat
// statements and status reads, and the key-trust screens. No Extension, MCP
// or dragpass-run code sends them over Native Messaging, so a frame that does
// is refused before the handler, the same as the other App-only actions.
var appRouteOnlyActions = []string{
	// identity
	proto.ActionAccountBindingSet,
	proto.ActionAccountBindingSignout,
	proto.ActionRotateUserKeypairPrepare,
	proto.ActionRotateUserKeypairPromote,
	proto.ActionDEKRotateToDeviceKey,
	proto.ActionDEKRotateToNewPassword,
	proto.ActionSaveSessionCode,
	proto.ActionRecoverySessionClose,
	proto.ActionDEKRewrapWithOldKeyToSelf,
	// archive keys, break-glass and quorum
	proto.ActionAccountArchiveKeyGenerate,
	proto.ActionArchiveKeyStatus,
	proto.ActionArchiveKeyRotateBegin,
	proto.ActionArchiveKeyRotateCommit,
	proto.ActionArchiveKeyRotateAbort,
	proto.ActionArchiveUnwrapAndRewrap,
	proto.ActionArchiveKeySplit,
	proto.ActionArchiveShareRewrap,
	proto.ActionArchiveSessionBegin,
	proto.ActionArchiveSessionEnd,
	proto.ActionArchiveQuorumCombineAndRewrap,
	// chat statements and reads that are not gated
	proto.ActionMLSLeafStatus,
	proto.ActionMLSLeafHandoverSign,
	proto.MLSRoomNameSeal,
	proto.MLSConversationStatus,
	proto.MLSEpochComparison,
	proto.MLSRejoinRequestSign,
	proto.MLSLeaveRequestSign,
	proto.MLSDeviceRevokeSign,
	// key-trust screens
	proto.ActionPeerKeyPinList,
	proto.ActionPeerKeyPinVerify,
	proto.ActionPeerKeySafetyNumber,
	proto.ActionPeerKeyChainEvaluate,
}

// appRouteOnlyPayload carries the fields the handlers above read first, so a
// handler that was reached would get past its decode and touch the store.
const appRouteOnlyPayload = `{"account_id":"11111111-1111-4111-8111-111111111111",` +
	`"owner_account_id":"11111111-1111-4111-8111-111111111111",` +
	`"peer_account_id":"22222222-2222-4222-8222-222222222222",` +
	`"org_id":"33333333-3333-4333-8333-333333333333","session_code":"x","password":"x",` +
	`"recovery_handle":"x","challenge_token":"x","signature":"x"}`

func TestAppRouteOnlyActionsAreRefusedOnNativeMessagingAndRunNothing(t *testing.T) {
	app, _, store := newLeaseApp(t)
	for _, action := range appRouteOnlyActions {
		before := store.calls.Load()
		frame, _ := json.Marshal(map[string]any{"action": action, "request_id": "x", "payload": json.RawMessage(appRouteOnlyPayload)})
		response := app.HandleRequest(frame)
		if response.Success || response.ErrorCode != ErrCodeChatAppCallerRequired || response.RequestID != "x" {
			t.Fatalf("%s from Native Messaging: %+v", action, response)
		}
		if store.calls.Load() != before {
			t.Fatalf("%s ran although it was refused", action)
		}
	}
}

func TestAppRouteOnlyActionsReachTheirHandlerFromTheApp(t *testing.T) {
	app, _, _ := newLeaseApp(t)
	for _, action := range appRouteOnlyActions {
		response := app.HandleAppRequest(sessionA, "", []byte(`{"action":"`+action+`","request_id":"x","payload":{}}`))
		if response.ErrorCode == ErrCodeChatAppCallerRequired || response.ErrorCode == ErrCodeChatRuntimeLeaseRequired {
			t.Fatalf("%s from the App was refused at the gate: %+v", action, response)
		}
	}
}
