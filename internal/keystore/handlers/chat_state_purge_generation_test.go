package handlers

import (
	"encoding/json"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/keychain"
)

func purgeRemovedConversations(t *testing.T, f *chatStateFixture, owner, generation string) int {
	t.Helper()
	resp := HandleChatStatePurge(f.deps, chatMarshal(t, map[string]any{
		"owner_account_id": owner, "expected_generation": generation,
	}))
	if !resp.Success {
		t.Fatalf("matching purge failed: %s (%s)", resp.Error, resp.ErrorCode)
	}
	raw, _ := json.Marshal(resp.Data)
	var data struct {
		Removed int `json:"removed_conversations"`
	}
	_ = json.Unmarshal(raw, &data)
	return data.Removed
}

// lv78: a purge that cannot prove which sign-in it belongs to must not become
// an unconditional delete. A stale request (an old logout delivered late, or
// one naming another account) would otherwise erase a newer sign-in's chat
// state. It is refused and the state stays.
func TestChatPurgeWithoutGenerationLeavesTheStateAlone(t *testing.T) {
	f := newChatStateFixture(t)
	binding, _, err := keychain.SetAccountBinding(f.deps.Store, chatAccountID, "alice", true)
	if err != nil {
		t.Fatal(err)
	}
	f.seedConversation(t, chatAccountID)
	resp := HandleChatStatePurge(f.deps, chatMarshal(t, map[string]any{"owner_account_id": chatAccountID}))
	if resp.Success {
		t.Fatal("a purge without an expected generation was accepted")
	}
	if got := purgeRemovedConversations(t, f, chatAccountID, binding.ChatStateGeneration); got != 1 {
		t.Fatalf("the refused purge erased state: %d conversations left to remove", got)
	}
}
