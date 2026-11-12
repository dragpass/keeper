package keystore

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/dragpass/keeper/config"
	"github.com/dragpass/keeper/internal/keystore/chatstate"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/testdouble"
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
			if response := app.HandleAppRequest(sessionA, epoch, []byte(gatedFrame)); !gatedActionRan(response) {
				t.Fatalf("the current App runtime was revoked by a purge that erased nothing: %+v", response)
			}
		})
	}
}

// sealKeyUndeletableStore fails every delete of a chat state seal key, so a
// purge runs its other destructive steps (anchors, the owner directory) and
// then fails on the last one.
type sealKeyUndeletableStore struct {
	SecretStore
}

func (s sealKeyUndeletableStore) Delete(service, account string) error {
	if strings.HasPrefix(account, config.ChatStateSealKeyPrefix) {
		return errors.New("seal key delete refused")
	}
	return s.SecretStore.Delete(service, account)
}

// lv78: a purge whose generation matched runs its destructive steps even when
// one of them fails, so the state it named is no longer intact. The runtime
// that was working on that state must stop, and the answer must not claim a
// complete erase.
func TestChatPurgeThatFailsPartwayRevokesTheRuntime(t *testing.T) {
	t.Setenv(chatstate.RootEnvVar, t.TempDir())
	clock := &leaseClock{now: time.Unix(1_800_000_000, 0)}
	store := sealKeyUndeletableStore{SecretStore: testdouble.NewMemorySecretStore()}
	app := NewApp(Deps{Store: store, Clock: clock.Now})
	generation := bindPurgeOwner(t, store)
	epoch := claimed(t, app, clock, holderA, sessionA, "")

	response := app.HandleRequest(purgeFrameWith(t, generation))
	if response.Success {
		t.Fatalf("a purge that could not delete the seal key reported success: %+v", response)
	}
	raw, _ := json.Marshal(response.Data)
	var data struct {
		Purged     bool `json:"purged"`
		Incomplete bool `json:"erase_incomplete"`
	}
	_ = json.Unmarshal(raw, &data)
	if data.Purged || !data.Incomplete {
		t.Fatalf("a partial erase must report erase_incomplete and not purged: %+v", response)
	}
	if reason := revokedReason(t, app.HandleAppRequest(sessionA, epoch, []byte(gatedFrame))); reason != ChatRuntimeRevokedPurged {
		t.Fatalf("revocation reason %q, want %q", reason, ChatRuntimeRevokedPurged)
	}
}

// lv78: the App sends chat_state_purge too, over its own local RPC session.
// On that caller path the revocation must also wait for the handler's answer:
// a purge from the App that erased nothing (an older sign-in's generation)
// must leave the current runtime alone, and a purge that erased the state it
// named must still revoke it.
func TestAppPurgeRevokesOnlyAfterItErasedTheNamedState(t *testing.T) {
	t.Run("stale generation leaves the runtime alone", func(t *testing.T) {
		app, clock, store := newLeaseApp(t)
		old := bindPurgeOwner(t, store)
		bindPurgeOwner(t, store) // a newer sign-in
		epoch := claimed(t, app, clock, holderA, sessionA, "")
		if response := app.HandleAppRequest(sessionA, epoch, purgeFrameWith(t, old)); !response.Success {
			t.Fatalf("the App purge naming an older sign-in was refused: %+v", response)
		}
		if response := app.HandleAppRequest(sessionA, epoch, []byte(gatedFrame)); !gatedActionRan(response) {
			t.Fatalf("the App's own purge that erased nothing revoked its runtime: %+v", response)
		}
	})
	t.Run("current generation revokes after the erase", func(t *testing.T) {
		app, clock, store := newLeaseApp(t)
		generation := bindPurgeOwner(t, store)
		epoch := claimed(t, app, clock, holderA, sessionA, "")
		if response := app.HandleAppRequest(sessionA, epoch, purgeFrameWith(t, generation)); !response.Success {
			t.Fatalf("the App purge of the current sign-in failed: %+v", response)
		}
		if reason := revokedReason(t, app.HandleAppRequest(sessionA, epoch, []byte(gatedFrame))); reason != ChatRuntimeRevokedPurged {
			t.Fatalf("revocation reason %q, want %q", reason, ChatRuntimeRevokedPurged)
		}
	})
}
