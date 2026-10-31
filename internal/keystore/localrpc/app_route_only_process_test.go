package localrpc

import (
	"encoding/json"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/proto"
)

const (
	routeOnlyOwner = "11111111-1111-4111-8111-111111111111"
	routeOnlyPeer  = "22222222-2222-4222-8222-222222222222"
	routeOnlyOrg   = "33333333-3333-4333-8333-333333333333"
)

// appRouteOnlyCalls pairs each action only an App route calls with that
// route and a body the route accepts. The answer may be the action's own
// refusal (nothing is set up in the isolated Keeper); what matters is that
// the action was admitted for the App and refused to a Native Messaging frame.
var appRouteOnlyCalls = []struct {
	action string
	path   string
	body   any
}{
	{proto.ActionAccountBindingSet, "/v1/account/binding", map[string]any{"account_id": routeOnlyOwner, "alias": "alice"}},
	{proto.ActionAccountBindingSignout, "/v1/account/binding/signout", map[string]any{}},
	{proto.ActionRotateUserKeypairPrepare, "/v1/account-key/rotate/prepare", map[string]any{}},
	{proto.ActionRotateUserKeypairPromote, "/v1/account-key/rotate/promote", map[string]any{}},
	{proto.ActionPersonalDEKBind, "/v1/auth/personal-dek/bind", map[string]any{}},
	{proto.ActionDEKRotateToDeviceKey, "/v1/auth/login/restore-device-master", map[string]any{}},
	{proto.ActionSaveSessionCode, "/v1/auth/signup/save-session-code", map[string]any{}},
	{proto.ActionRecoverySessionClose, "/v1/auth/recovery/close", map[string]any{}},
	{proto.ActionDEKRewrapWithOldKeyToSelf, "/v1/auth/recovery/rewrap-group-dek", map[string]any{}},
	{proto.ActionAccountArchiveKeyGenerate, "/v1/archive/account_archive_key_generate", map[string]any{}},
	{proto.ActionArchiveKeyStatus, "/v1/archive/archive_key_status", map[string]any{}},
	{proto.ActionArchiveKeyRotateBegin, "/v1/archive/archive_key_rotate_begin", map[string]any{}},
	{proto.ActionArchiveKeyRotateCommit, "/v1/archive/archive_key_rotate_commit", map[string]any{}},
	{proto.ActionArchiveKeyRotateAbort, "/v1/archive/archive_key_rotate_abort", map[string]any{}},
	{proto.ActionArchiveUnwrapAndRewrap, "/v1/archive/archive_unwrap_and_rewrap", map[string]any{
		"wrapped_for_archive_b64": "AAAA", "account_archive_public_key": "x",
	}},
	{proto.ActionArchiveKeySplit, "/v1/archive/archive_key_split", map[string]any{}},
	{proto.ActionArchiveShareRewrap, "/v1/archive/archive_share_rewrap", map[string]any{}},
	{proto.ActionArchiveSessionBegin, "/v1/archive/archive_session_begin", map[string]any{}},
	{proto.ActionArchiveSessionEnd, "/v1/archive/archive_session_end", map[string]any{}},
	{proto.ActionArchiveQuorumCombineAndRewrap, "/v1/archive/archive_quorum_combine_and_rewrap", map[string]any{
		"rewrapped_shares": []any{}, "wrapped_old_dek_b64": "AAAA", "owner_account_id": routeOnlyOwner,
		"recipients": []any{map[string]any{"account_id": routeOnlyPeer, "public_key": "x"}},
	}},
	{proto.ActionMLSLeafStatus, "/v1/chat/mls_leaf_status", map[string]any{}},
	{proto.ActionMLSLeafHandoverSign, "/v1/chat/mls_leaf_handover_sign", map[string]any{}},
	{proto.MLSRoomNameSeal, "/v1/chat/mls_room_name_seal", map[string]any{}},
	{proto.MLSConversationStatus, "/v1/chat/mls_conversation_status", map[string]any{}},
	{proto.MLSEpochComparison, "/v1/chat/mls_epoch_comparison", map[string]any{}},
	{proto.MLSRejoinRequestSign, "/v1/chat/mls_rejoin_request_sign", map[string]any{}},
	{proto.MLSLeaveRequestSign, "/v1/chat/mls_leave_request_sign", map[string]any{}},
	{proto.MLSDeviceRevokeSign, "/v1/chat/mls_device_revoke_sign", map[string]any{}},
	{proto.ActionPeerKeyPinList, "/v1/peer-key/pin-list", map[string]any{"owner_account_id": routeOnlyOwner}},
	{proto.ActionPeerKeyPinVerify, "/v1/peer-key/pin-verify", map[string]any{}},
	{proto.ActionPeerKeySafetyNumber, "/v1/peer-key/safety-number", map[string]any{}},
	{proto.ActionPeerKeyChainEvaluate, "/v1/peer-key/chain-evaluate", map[string]any{}},
}

// A real owner admits each of these actions through its App route and
// refuses the same action to a Native Messaging host proxying to it. The
// password change composes dek_rotate_to_device_key and
// dek_rotate_to_new_password inside Keeper, so it is checked as one route.
func TestAppRouteOnlyActionsRunFromTheAppAndAreRefusedToNativeMessaging(t *testing.T) {
	dir, address := t.TempDir(), freeLoopbackAddress(t)
	owner := startAppService(t, dir, address)
	client := &testAppClient{address: address, origin: testOrigin, pairingKey: pairingKeyOf(t, dir)}
	if err := client.open(); err != nil {
		t.Fatalf("open: %v\n%s", err, owner.stderr.String())
	}
	// A host proxies only to an owner it can prove, with the same local secret.
	host := startNativeHost(t, dir, address)

	calls := append(appRouteOnlyCalls, struct {
		action string
		path   string
		body   any
	}{proto.ActionDEKRotateToNewPassword, "/v1/auth/password/rewrap", map[string]any{
		"password": "x", "encrypted_dek_b64": "AAAA", "new_password": "y",
	}})
	for _, call := range calls {
		response, err := client.call(call.path, call.body)
		if err != nil {
			t.Fatalf("%s (%s) from the App: %v\n%s", call.action, call.path, err, owner.stderr.String())
		}
		if response.ErrorCode == "chat_app_caller_required" || response.ErrorCode == "chat_runtime_lease_required" {
			t.Fatalf("%s from the App was refused at the gate: %+v", call.action, response)
		}
		frame, _ := json.Marshal(map[string]any{"action": call.action, "request_id": "r", "payload": call.body})
		refused := host.send(t, string(frame))
		if refused.Success || refused.ErrorCode != "chat_app_caller_required" || refused.RequestID != "r" {
			t.Fatalf("%s from Native Messaging: %+v", call.action, refused)
		}
	}
}
