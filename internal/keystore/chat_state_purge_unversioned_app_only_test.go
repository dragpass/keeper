//go:build !keeper_killseam

package keystore

import "testing"

// lv78 A3: only the App cleans up state an older Keeper left unversioned. A
// Native Messaging frame asking for it is refused before the handler runs,
// so nothing is read or erased, whatever the request names.
func TestUnversionedPurgeIsRefusedToNativeMessaging(t *testing.T) {
	app, _, store := newLeaseApp(t)
	before := store.calls.Load()
	frame := `{"action":"chat_state_purge_unversioned","request_id":"x","payload":{"owner_account_id":"a1111111-1111-4111-8111-111111111111","require_no_generation":true,"require_not_signed_in":true}}`
	response := app.HandleRequest([]byte(frame))
	if response.Success || response.ErrorCode != ErrCodeChatAppCallerRequired {
		t.Fatalf("chat_state_purge_unversioned over Native Messaging: %+v", response)
	}
	if store.calls.Load() != before {
		t.Fatal("the refused request read the keychain")
	}
}
