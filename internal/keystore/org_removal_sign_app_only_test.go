//go:build !keeper_e2e

package keystore

import "testing"

// lv78: org_member_removal_sign signs with the account key, and its only
// production caller is the App. A release build refuses it to a Native
// Messaging frame before the handler runs, so no key is read.
func TestOrgMemberRemovalSignIsRefusedToNativeMessaging(t *testing.T) {
	app, _, store := newLeaseApp(t)
	before := store.calls.Load()
	frame := `{"action":"org_member_removal_sign","request_id":"x","payload":{"org_id":"a1111111-1111-4111-8111-111111111111","removed_account_id":"b2222222-2222-4222-8222-222222222222","admin_account_id":"c3333333-3333-4333-8333-333333333333"}}`
	response := app.HandleRequest([]byte(frame))
	if response.Success || response.ErrorCode != ErrCodeChatAppCallerRequired {
		t.Fatalf("org_member_removal_sign over Native Messaging: %+v", response)
	}
	if store.calls.Load() != before {
		t.Fatal("the refused request read the keychain")
	}
}
