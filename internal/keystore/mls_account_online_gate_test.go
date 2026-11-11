package keystore

import (
	"encoding/json"
	"testing"
)

// lv78 A1b: the account-level MLS actions that use the device or leaf key no
// longer run on the App lease alone. A call on the action's own route, without
// a verified account decision, is refused before its handler reads anything.
func TestAccountMLSActionWithoutADecisionIsRefused(t *testing.T) {
	for _, action := range []string{
		"mls_leaf_declare", "mls_leaf_promote", "mls_key_package_generate",
		"mls_leaf_handover_sign", "mls_device_revoke_sign", "org_member_removal_sign",
	} {
		t.Run(action, func(t *testing.T) {
			app, clock, store := newLeaseApp(t)
			epoch := claimed(t, app, clock, holderA, sessionA, "")
			frame, _ := json.Marshal(map[string]any{"action": action, "request_id": "r-1", "payload": map[string]any{}})
			before := store.calls.Load()
			response := app.HandleAppFencedRequest(sessionA, epoch, "", true, frame)
			if response.Success || response.ErrorCode != ErrCodeChatOnlineDecisionRequired {
				t.Fatalf("%s without a decision: %+v", action, response)
			}
			if store.calls.Load() != before {
				t.Fatalf("%s touched the keychain before its refusal", action)
			}
		})
	}
}
