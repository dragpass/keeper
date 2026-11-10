package keystore

import (
	"encoding/json"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/keychain"
)

const purgeOwner = "a1111111-1111-4111-8111-111111111111"

// purgeFrameWith is a chat_state_purge frame naming generation ("" omits it).
func purgeFrameWith(t *testing.T, generation string) []byte {
	t.Helper()
	payload := map[string]any{"owner_account_id": purgeOwner}
	if generation != "" {
		payload["expected_generation"] = generation
	}
	frame, err := json.Marshal(map[string]any{"action": "chat_state_purge", "request_id": "p-1", "payload": payload})
	if err != nil {
		t.Fatal(err)
	}
	return frame
}

// bindPurgeOwner signs purgeOwner in on the store and returns its chat state
// generation, as account_binding_set does.
func bindPurgeOwner(t *testing.T, store keychain.SecretStore) string {
	t.Helper()
	binding, _, err := keychain.SetAccountBinding(store, purgeOwner, "alice", true)
	if err != nil {
		t.Fatal(err)
	}
	return binding.ChatStateGeneration
}

// lv78: a purge that erases nothing, because it names an older sign-in's
// generation or none at all, must not revoke the App runtime of the current
// sign-in. Only a purge that erased the state it named revokes.
func TestChatPurgeThatErasesNothingLeavesTheAppRuntimeAlone(t *testing.T) {
	for name, frame := range map[string]func(old string) []byte{
		"stale generation": func(old string) []byte { return purgeFrameWith(t, old) },
		"no generation":    func(string) []byte { return purgeFrameWith(t, "") },
	} {
		t.Run(name, func(t *testing.T) {
			app, clock, store := newLeaseApp(t)
			old := bindPurgeOwner(t, store)
			bindPurgeOwner(t, store) // a newer sign-in
			epoch := claimed(t, app, clock, holderA, sessionA, "")
			app.HandleRequest(frame(old))
			if response := app.HandleAppRequest(sessionA, epoch, []byte(gatedFrame)); !response.Success {
				t.Fatalf("the current App runtime was revoked by a purge that erased nothing: %+v", response)
			}
		})
	}
}
