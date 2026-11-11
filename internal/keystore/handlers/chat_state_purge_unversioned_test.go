package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/dragpass/keeper/config"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// lv78 A3: chat_state_purge_unversioned erases the chat state an older Keeper
// (0.0.58) left with no generation slot, and only when the evidence says no
// sign-in owns it: the account has no generation slot and the binding is not
// that account's signed-in state. Both are read under the keychain process
// lock, in the same hold as the erase.

const otherChatAccountID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"

// legacyBinding writes the binding record a 0.0.58 Keeper wrote: no chat
// state generation slot beside it.
func legacyBinding(t *testing.T, f *chatStateFixture, accountID string, signedOut bool) {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"v": 1, "account_id": accountID, "alias": "alice", "generation": 3, "signed_out": signedOut,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.deps.Store.Set(config.Service, config.AccountBinding, string(raw)); err != nil {
		t.Fatal(err)
	}
}

func unversionedPurge(t *testing.T, f *chatStateFixture, payload map[string]any) proto.BaseResponse {
	t.Helper()
	return HandleChatStatePurgeUnversioned(f.deps, chatMarshal(t, payload))
}

func unversionedPurgeFor(accountID string) map[string]any {
	return map[string]any{
		"owner_account_id":      accountID,
		"require_no_generation": true,
		"require_not_signed_in": true,
	}
}

type unversionedPurgeData struct {
	Purged  bool   `json:"purged"`
	Removed int    `json:"removed_conversations"`
	Kept    string `json:"kept"`
}

func unversionedData(t *testing.T, resp proto.BaseResponse) unversionedPurgeData {
	t.Helper()
	if !resp.Success {
		t.Fatalf("unversioned purge failed: %s (%s)", resp.Error, resp.ErrorCode)
	}
	raw, _ := json.Marshal(resp.Data)
	var data unversionedPurgeData
	if err := json.Unmarshal(raw, &data); err != nil {
		t.Fatal(err)
	}
	return data
}

// conversationsLeft counts the account's conversations still on disk by
// erasing them under a fresh sign-in, after the call under test has answered.
func conversationsLeft(t *testing.T, f *chatStateFixture, accountID string) int {
	t.Helper()
	binding, _, err := keychain.SetAccountBinding(f.deps.Store, accountID, "probe", true)
	if err != nil {
		t.Fatal(err)
	}
	return purgeRemovedConversations(t, f, accountID, binding.ChatStateGeneration)
}

func TestUnversionedPurgeErasesStateNoSignInOwns(t *testing.T) {
	cases := []struct {
		name    string
		binding func(t *testing.T, f *chatStateFixture)
	}{
		{"another account signed in", func(t *testing.T, f *chatStateFixture) {
			legacyBinding(t, f, otherChatAccountID, false)
		}},
		{"this account signed out", func(t *testing.T, f *chatStateFixture) {
			legacyBinding(t, f, chatAccountID, true)
		}},
		{"no binding", func(*testing.T, *chatStateFixture) {}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newChatStateFixture(t)
			tc.binding(t, f)
			f.seedConversation(t, chatAccountID)

			data := unversionedData(t, unversionedPurge(t, f, unversionedPurgeFor(chatAccountID)))
			if !data.Purged || data.Removed != 1 || data.Kept != "" {
				t.Fatalf("got %+v, want the state erased", data)
			}
			if left := conversationsLeft(t, f, chatAccountID); left != 0 {
				t.Fatalf("%d conversations survived the erase", left)
			}
		})
	}
}

// A 0.0.58 binding restored without renew never rotates the generation, so a
// live session can sit on state with no slot. The binding decides then.
func TestUnversionedPurgeKeepsTheSignedInAccountsState(t *testing.T) {
	f := newChatStateFixture(t)
	legacyBinding(t, f, chatAccountID, false)
	f.seedConversation(t, chatAccountID)

	data := unversionedData(t, unversionedPurge(t, f, unversionedPurgeFor(chatAccountID)))
	if data.Purged || data.Removed != 0 || data.Kept != "account_signed_in" {
		t.Fatalf("got %+v, want the signed-in state kept", data)
	}
	if left := conversationsLeft(t, f, chatAccountID); left != 1 {
		t.Fatalf("%d conversations left, want the signed-in state intact", left)
	}
}

// A generation slot means a Keeper that names its sign-ins wrote this state:
// only the conditional purge with that generation may erase it, whoever is
// bound now.
func TestUnversionedPurgeKeepsStateThatHasAGeneration(t *testing.T) {
	for _, tc := range []struct {
		name    string
		binding func(t *testing.T, f *chatStateFixture)
	}{
		{"signed out since", func(t *testing.T, f *chatStateFixture) {
			if _, _, err := keychain.SignOutAccountBinding(f.deps.Store); err != nil {
				t.Fatal(err)
			}
		}},
		{"another account signed in since", func(t *testing.T, f *chatStateFixture) {
			if _, _, err := keychain.SetAccountBinding(f.deps.Store, otherChatAccountID, "bob", true); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newChatStateFixture(t)
			if _, _, err := keychain.SetAccountBinding(f.deps.Store, chatAccountID, "alice", true); err != nil {
				t.Fatal(err)
			}
			f.seedConversation(t, chatAccountID)
			tc.binding(t, f)

			data := unversionedData(t, unversionedPurge(t, f, unversionedPurgeFor(chatAccountID)))
			if data.Purged || data.Removed != 0 || data.Kept != "generation_present" {
				t.Fatalf("got %+v, want state with a generation kept", data)
			}
			if left := conversationsLeft(t, f, chatAccountID); left != 1 {
				t.Fatalf("%d conversations left, want the state intact", left)
			}
		})
	}
}

// The conditions are part of the request, so no caller reaches this erase by
// accident or by omission: anything but both named is refused, and nothing is
// erased.
func TestUnversionedPurgeRefusesARequestThatDoesNotNameBothConditions(t *testing.T) {
	for name, payload := range map[string]map[string]any{
		"no conditions":          {"owner_account_id": chatAccountID},
		"generation unchecked":   {"owner_account_id": chatAccountID, "require_no_generation": false, "require_not_signed_in": true},
		"binding unchecked":      {"owner_account_id": chatAccountID, "require_no_generation": true, "require_not_signed_in": false},
		"only the binding named": {"owner_account_id": chatAccountID, "require_not_signed_in": true},
		"only the generation":    {"owner_account_id": chatAccountID, "require_no_generation": true},
		"an expected generation": {"owner_account_id": chatAccountID, "require_no_generation": true, "require_not_signed_in": true, "expected_generation": "AAAAAAAAAAAAAAAAAAAAAA"},
		"not an account id":      {"owner_account_id": "alice", "require_no_generation": true, "require_not_signed_in": true},
		"conditions as strings":  {"owner_account_id": chatAccountID, "require_no_generation": "true", "require_not_signed_in": "true"},
		"conditions as null":     {"owner_account_id": chatAccountID, "require_no_generation": nil, "require_not_signed_in": nil},
		"conditions as numbers":  {"owner_account_id": chatAccountID, "require_no_generation": 1, "require_not_signed_in": 1},
		"owner missing entirely": {"require_no_generation": true, "require_not_signed_in": true},
	} {
		t.Run(name, func(t *testing.T) {
			f := newChatStateFixture(t)
			f.seedConversation(t, chatAccountID)
			resp := unversionedPurge(t, f, payload)
			if resp.Success || resp.ErrorCode != "CHAT_STATE_INVALID_INPUT" {
				t.Fatalf("got success=%t code=%q, want CHAT_STATE_INVALID_INPUT", resp.Success, resp.ErrorCode)
			}
			if left := conversationsLeft(t, f, chatAccountID); left != 1 {
				t.Fatalf("%d conversations left, want the refused request to erase nothing", left)
			}
		})
	}
}

// A chat login interrupted between its fence and its binding write may be
// about to give this account a slot: nothing is decided until it finishes.
func TestUnversionedPurgeRefusesWhileAChatLoginIsCommitting(t *testing.T) {
	f := newChatStateFixture(t)
	legacyBinding(t, f, otherChatAccountID, false)
	f.seedConversation(t, chatAccountID)
	fence, _ := json.Marshal(map[string]any{"v": 1, "committing": true, "commit_account_id": chatAccountID})
	if err := f.deps.Store.Set(config.Service, "chat_login_fence_v1", string(fence)); err != nil {
		t.Fatal(err)
	}

	resp := unversionedPurge(t, f, unversionedPurgeFor(chatAccountID))
	if resp.Success {
		t.Fatal("an unversioned purge ran during an unfinished chat login")
	}
	if err := f.deps.Store.Delete(config.Service, "chat_login_fence_v1"); err != nil {
		t.Fatal(err)
	}
	if left := conversationsLeft(t, f, chatAccountID); left != 1 {
		t.Fatalf("%d conversations left, want the state intact", left)
	}
}

// The slot is per account: another account's generation says nothing about
// this one, and the erase reaches only the named account.
func TestUnversionedPurgeReachesOnlyTheNamedAccount(t *testing.T) {
	f := newChatStateFixture(t)
	if _, _, err := keychain.SetAccountBinding(f.deps.Store, otherChatAccountID, "bob", true); err != nil {
		t.Fatal(err)
	}
	f.seedConversation(t, chatAccountID)
	f.seedConversation(t, otherChatAccountID)

	data := unversionedData(t, unversionedPurge(t, f, unversionedPurgeFor(chatAccountID)))
	if !data.Purged || data.Removed != 1 {
		t.Fatalf("got %+v, want the unversioned account's state erased", data)
	}
	if left := conversationsLeft(t, f, otherChatAccountID); left != 1 {
		t.Fatalf("%d conversations left for the bound account, want 1", left)
	}
}

// Guards the helper the tests above rely on to read "no slot".
func TestLegacyBindingHasNoGenerationSlot(t *testing.T) {
	f := newChatStateFixture(t)
	legacyBinding(t, f, chatAccountID, false)
	sum := sha256.Sum256([]byte(chatAccountID))
	if _, err := f.deps.Store.Get(config.Service, "chat_state_generation_"+hex.EncodeToString(sum[:])); err == nil {
		t.Fatal("the legacy binding helper wrote a generation slot")
	}
}
