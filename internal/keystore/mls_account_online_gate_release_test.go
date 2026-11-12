//go:build !keeper_e2e && !keeper_killseam

package keystore

import (
	"encoding/json"
	"testing"
)

// Native Messaging (the Extension, any local process) runs none of them in a
// release build: org_member_removal_sign was the one still reachable there.
func TestAccountMLSActionOverNativeMessagingIsRefused(t *testing.T) {
	for _, action := range []string{"org_member_removal_sign", "mls_device_revoke_sign", "mls_leaf_declare"} {
		t.Run(action, func(t *testing.T) {
			app, _, store := newLeaseApp(t)
			frame, _ := json.Marshal(map[string]any{"action": action, "request_id": "r-1", "payload": map[string]any{
				"org_id": "b2222222-2222-4222-8222-222222222222", "removed_account_id": "a9999999-1111-4111-8111-111111111111",
				"admin_account_id": "a1111111-1111-4111-8111-111111111111",
			}})
			before := store.calls.Load()
			response := app.HandleRequest(frame)
			if response.Success || (response.ErrorCode != ErrCodeChatOnlineDecisionRequired && response.ErrorCode != ErrCodeChatAppCallerRequired) {
				t.Fatalf("%s over Native Messaging: %+v", action, response)
			}
			if store.calls.Load() != before {
				t.Fatalf("%s touched the keychain before its refusal", action)
			}
		})
	}
}
