package handlers

import (
	"encoding/json"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/keychain"
)

// A decision made before a fresh sign-in must not erase its chat state.
func TestConditionalChatPurgePreservesANewerSignIn(t *testing.T) {
	f := newChatStateFixture(t)
	if _, _, err := keychain.SetAccountBinding(f.deps.Store, chatAccountID, "alice", true); err != nil {
		t.Fatal(err)
	}
	status := HandleDeviceAccountStatus(f.deps, struct{}{})
	raw, _ := json.Marshal(status.Data)
	var before map[string]any
	if err := json.Unmarshal(raw, &before); err != nil {
		t.Fatal(err)
	}
	generation, ok := before["chat_state_generation"].(string)
	if !ok || generation == "" {
		t.Fatal("status did not supply a chat state generation")
	}
	if _, _, err := keychain.SetAccountBinding(f.deps.Store, chatAccountID, "alice", true); err != nil {
		t.Fatal(err)
	}
	f.seedConversation(t, chatAccountID)
	response := HandleChatStatePurge(f.deps, chatMarshal(t, map[string]any{
		"owner_account_id": chatAccountID, "expected_generation": generation,
	}))
	if !response.Success {
		t.Fatal("conditional mismatch must be a successful no-op")
	}
	data, _ := json.Marshal(response.Data)
	var result map[string]any
	_ = json.Unmarshal(data, &result)
	if result["purged"] != false {
		t.Fatal("a newer sign-in must not be purged")
	}
	if got := f.purge(t, chatAccountID); !got.Success {
		t.Fatal("legacy purge failed")
	} else {
		value, _ := json.Marshal(got.Data)
		var removed map[string]any
		_ = json.Unmarshal(value, &removed)
		if removed["removed_conversations"] != float64(1) {
			t.Fatal("conditional no-op erased the newer state")
		}
	}
}

func TestConditionalChatPurgeMatchingGenerationErasesState(t *testing.T) {
	f := newChatStateFixture(t)
	binding, _, err := keychain.SetAccountBinding(f.deps.Store, chatAccountID, "alice", true)
	if err != nil {
		t.Fatal(err)
	}
	f.seedConversation(t, chatAccountID)
	response := HandleChatStatePurge(f.deps, chatMarshal(t, map[string]any{
		"owner_account_id": chatAccountID, "expected_generation": binding.ChatStateGeneration,
	}))
	if !response.Success {
		t.Fatal("matching conditional purge failed")
	}
	raw, _ := json.Marshal(response.Data)
	var data map[string]any
	_ = json.Unmarshal(raw, &data)
	if data["purged"] != true || data["removed_conversations"] != float64(1) {
		t.Fatal("matching purge did not erase the conversation")
	}
}

func TestChatPurgeGenerationNeverReusesADeletedBinding(t *testing.T) {
	f := newChatStateFixture(t)
	first, _, err := keychain.SetAccountBinding(f.deps.Store, chatAccountID, "alice", true)
	if err != nil {
		t.Fatal(err)
	}
	if err := keychain.DeleteAccountBinding(f.deps.Store); err != nil {
		t.Fatal(err)
	}
	next, _, err := keychain.SetAccountBinding(f.deps.Store, chatAccountID, "alice", true)
	if err != nil {
		t.Fatal(err)
	}
	if first.Generation != next.Generation {
		t.Fatal("test must exercise repeated legacy generation")
	}
	if first.ChatStateGeneration == "" || first.ChatStateGeneration == next.ChatStateGeneration {
		t.Fatal("chat generation repeated across binding recreation")
	}
}

func TestConditionalChatPurgeRejectsAnExplicitEmptyOrNullGeneration(t *testing.T) {
	for _, generation := range []any{"", nil} {
		f := newChatStateFixture(t)
		f.seedConversation(t, chatAccountID)
		response := HandleChatStatePurge(f.deps, chatMarshal(t, map[string]any{
			"owner_account_id": chatAccountID, "expected_generation": generation,
		}))
		if response.Success {
			t.Fatal("invalid conditional generation became an unconditional purge")
		}
	}
}
