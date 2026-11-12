//go:build keeper_e2e && !keeper_killseam

package keystore

import (
	"encoding/json"
	"testing"
)

// A keeper_e2e build keeps serving the Extension's E2E member fixture its
// organization removal statement over Native Messaging without an account
// decision (compile time only); no other account-level action is exempt.
func TestE2EBuildExemptsOnlyTheRemovalFixtureOverNative(t *testing.T) {
	app, _, _ := newLeaseApp(t)
	frame, _ := json.Marshal(map[string]any{"action": "org_member_removal_sign", "request_id": "r-1", "payload": map[string]any{
		"org_id": "b2222222-2222-4222-8222-222222222222", "removed_account_id": "a9999999-1111-4111-8111-111111111111",
		"admin_account_id": "a1111111-1111-4111-8111-111111111111",
	}})
	if response := app.HandleRequest(frame); response.ErrorCode == ErrCodeChatOnlineDecisionRequired || response.ErrorCode == ErrCodeChatAppCallerRequired {
		t.Fatalf("the E2E removal fixture was refused: %+v", response)
	}
	for _, action := range []string{"mls_device_revoke_sign", "mls_leaf_declare", "mls_leaf_handover_sign"} {
		frame, _ := json.Marshal(map[string]any{"action": action, "request_id": "r-1", "payload": map[string]any{}})
		if response := app.HandleRequest(frame); response.Success ||
			(response.ErrorCode != ErrCodeChatOnlineDecisionRequired && response.ErrorCode != ErrCodeChatAppCallerRequired) {
			t.Fatalf("%s over Native in an E2E build: %+v", action, response)
		}
	}
}
