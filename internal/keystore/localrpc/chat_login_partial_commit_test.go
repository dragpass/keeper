package localrpc

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/dragpass/keeper/config"
	"github.com/dragpass/keeper/internal/keystore/handlers"
	"github.com/dragpass/keeper/internal/keystore/keychain"
)

type chatLoginWriteFault struct {
	keychain.SecretStore
	target     string
	generation string
	afterWrite bool
}

func (s *chatLoginWriteFault) Set(service, account, value string) error {
	var fence struct {
		Generation string `json:"generation"`
	}
	_ = json.Unmarshal([]byte(value), &fence)
	if account == s.target && (account != "chat_login_fence_v1" || fence.Generation == s.generation) {
		if s.afterWrite {
			if err := s.SecretStore.Set(service, account, value); err != nil {
				return err
			}
		}
		return errors.New("injected write failure")
	}
	return s.SecretStore.Set(service, account, value)
}

func TestPartialChatLoginCommitCannotTurnOldPurgeIntoASuccessfulSkip(t *testing.T) {
	for _, target := range []string{config.AccountBinding, "chat_login_fence_v1"} {
		t.Run(target, func(t *testing.T) {
			s := newTestServer(t)
			keys := routeKeypair(t)
			if err := keychain.SavePublicKey(s.app.Store, keys.PublicKey); err != nil {
				t.Fatal(err)
			}
			token, csrf := openTestSession(t, s)
			old := loginForFence(t, s, token, csrf, "AAAAAAAAAAAAAAAAAAAAAA", "")
			state, err := keychain.ReadChatLogin(s.app.Store)
			if err != nil {
				t.Fatal(err)
			}
			_, prepared, _ := callRoute(t, s, token, csrf, "/v1/account/chat-session/prepare", map[string]any{
				"intent_id": "BBBBBBBBBBBBBBBBBBBBBB", "predecessor_generation": old, "after_sequence": state.PreparationSequence,
			})
			if !prepared.Success {
				t.Fatal("prepare failed")
			}
			pending, _ := keychain.ReadChatLogin(s.app.Store)
			s.app.Store = &chatLoginWriteFault{SecretStore: s.app.Store, target: target, generation: pending.PendingGeneration}
			_, committed, _ := callRoute(t, s, token, csrf, "/v1/account/chat-session/commit", map[string]string{
				"intent_id": "BBBBBBBBBBBBBBBBBBBBBB", "account_id": routeOwner, "alias": "alice",
			})
			if committed.Success {
				t.Fatal("fault was not injected")
			}
			body, _ := json.Marshal(map[string]string{"owner_account_id": routeOwner, "expected_generation": old})
			result := handlers.HandleChatStatePurge(s.app.HandlersDeps(), body)
			if result.Success {
				t.Fatal("partially installed generation falsely confirmed an old purge")
			}
		})
	}
}

func TestLostFinalChatBindingWriteAnswerRecoversWithoutHoldingTheOldLease(t *testing.T) {
	s := newTestServer(t)
	keys := routeKeypair(t)
	_ = keychain.SavePublicKey(s.app.Store, keys.PublicKey)
	token, csrf := openTestSession(t, s)
	old := loginForFence(t, s, token, csrf, "AAAAAAAAAAAAAAAAAAAAAA", "")
	grant := callFencedRoute(t, s, token, csrf, old, "", "/v1/chat/runtime/claim", map[string]any{"holder_id": routeHolder, "sequence": 1})
	if !grant.Success {
		t.Fatal("first grant failed")
	}
	state, _ := keychain.ReadChatLogin(s.app.Store)
	_, prepared, _ := callRoute(t, s, token, csrf, "/v1/account/chat-session/prepare", map[string]any{"intent_id": "BBBBBBBBBBBBBBBBBBBBBB", "predecessor_generation": old, "after_sequence": state.PreparationSequence})
	if !prepared.Success {
		t.Fatal("prepare failed")
	}
	pending, _ := keychain.ReadChatLogin(s.app.Store)
	fault := &chatLoginWriteFault{SecretStore: s.app.Store, target: "chat_login_fence_v1", generation: pending.PendingGeneration, afterWrite: true}
	s.app.Store = fault
	body := map[string]string{"intent_id": "BBBBBBBBBBBBBBBBBBBBBB", "account_id": routeOwner, "alias": "alice"}
	_, failed, _ := callRoute(t, s, token, csrf, "/v1/account/chat-session/commit", body)
	if failed.Success {
		t.Fatal("fault was not injected")
	}
	fault.target = ""
	_, retried, _ := callRoute(t, s, token, csrf, "/v1/account/chat-session/commit", body)
	if !retried.Success {
		t.Fatal("same intent did not recover")
	}
	result := callFencedRoute(t, s, token, csrf, pending.PendingGeneration, "", "/v1/chat/runtime/claim", map[string]any{"holder_id": "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC", "sequence": 1})
	if !result.Success {
		t.Fatal("the recovered binding kept the old login's lease")
	}
}
