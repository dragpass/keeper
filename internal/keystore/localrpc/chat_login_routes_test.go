package localrpc

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

func TestChatLoginCommitRetryKeepsOneGeneration(t *testing.T) {
	s := newTestServer(t)
	keys := routeKeypair(t)
	if err := keychain.SavePublicKey(s.app.Store, keys.PublicKey); err != nil {
		t.Fatal(err)
	}
	token, csrf := openTestSession(t, s)
	call := func(path string, body any) map[string]any {
		t.Helper()
		code, result, _ := callRoute(t, s, token, csrf, path, body)
		if code != http.StatusOK || !result.Success {
			t.Fatalf("login route failed: status=%d", code)
		}
		var data map[string]any
		if err := json.Unmarshal(result.Data, &data); err != nil {
			t.Fatal("invalid response")
		}
		return data
	}
	intent := "AAAAAAAAAAAAAAAAAAAAAA"
	call("/v1/account/chat-session/prepare", map[string]string{"intent_id": intent, "predecessor_generation": ""})
	body := map[string]string{"intent_id": intent, "account_id": routeOwner, "alias": "alice"}
	first := call("/v1/account/chat-session/commit", body)
	second := call("/v1/account/chat-session/commit", body)
	if first["generation"] == "" || first["generation"] != second["generation"] {
		t.Fatal("retry rotated the generation")
	}
	if first["previous_permits_invalidated"] != false {
		t.Fatal("binding alone must not claim permit invalidation")
	}
}

func TestConfirmedChatLoginRejectsLegacyClaims(t *testing.T) {
	s := newTestServer(t)
	keys := routeKeypair(t)
	if err := keychain.SavePublicKey(s.app.Store, keys.PublicKey); err != nil {
		t.Fatal(err)
	}
	token, csrf := openTestSession(t, s)
	for _, step := range []struct {
		path string
		body any
	}{
		{"/v1/account/chat-session/prepare", map[string]string{"intent_id": "AAAAAAAAAAAAAAAAAAAAAA", "predecessor_generation": ""}},
		{"/v1/account/chat-session/commit", map[string]string{"intent_id": "AAAAAAAAAAAAAAAAAAAAAA", "account_id": routeOwner, "alias": "alice"}},
	} {
		code, result, _ := callRoute(t, s, token, csrf, step.path, step.body)
		if code != http.StatusOK || !result.Success {
			t.Fatal("setup binding failed")
		}
	}
	_, claim, _ := callRoute(t, s, token, csrf, "/v1/chat/runtime/claim", map[string]string{"holder_id": routeHolder})
	if claim.Success || claim.ErrorCode != "chat_session_binding_required" {
		t.Fatal("legacy claim bypassed the confirmed session fence")
	}
}

func loginForFence(t *testing.T, s *Server, token, csrf, id, predecessor string) string {
	t.Helper()
	state, err := keychain.ReadChatLogin(s.app.Store)
	if err != nil {
		t.Fatal("status read failed")
	}
	for _, step := range []struct {
		path string
		body any
	}{
		{"/v1/account/chat-session/prepare", map[string]any{"intent_id": id, "predecessor_generation": predecessor, "after_sequence": state.PreparationSequence}},
		{"/v1/account/chat-session/commit", map[string]string{"intent_id": id, "account_id": routeOwner, "alias": "alice"}},
	} {
		code, result, _ := callRoute(t, s, token, csrf, step.path, step.body)
		if code != http.StatusOK || !result.Success {
			t.Fatal("fence setup failed")
		}
		if step.path == "/v1/account/chat-session/commit" {
			var data struct {
				Generation string `json:"generation"`
			}
			_ = json.Unmarshal(result.Data, &data)
			return data.Generation
		}
	}
	t.Fatal("missing commit")
	return ""
}

func callFencedRoute(t *testing.T, s *Server, token, csrf, generation, epoch, path string, body any) routeResult {
	t.Helper()
	raw, _ := json.Marshal(body)
	response := sessionRequestWithEpoch(s, http.MethodPost, path, string(raw), token, csrf, testOrigin, true, epoch, generation)
	if response.Code != http.StatusOK {
		t.Fatalf("fenced route status=%d", response.Code)
	}
	var result routeResult
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal("invalid fenced answer")
	}
	return result
}

func TestLateChatLoginCommitCannotReplaceANewerIntent(t *testing.T) {
	s := newTestServer(t)
	keys := routeKeypair(t)
	_ = keychain.SavePublicKey(s.app.Store, keys.PublicKey)
	token, csrf := openTestSession(t, s)
	const old = "AAAAAAAAAAAAAAAAAAAAAA"
	const fresh = "BBBBBBBBBBBBBBBBBBBBBB"
	_, prepared, _ := callRoute(t, s, token, csrf, "/v1/account/chat-session/prepare", map[string]string{"intent_id": old, "predecessor_generation": ""})
	if !prepared.Success {
		t.Fatal("prepare failed")
	}
	generation := loginForFence(t, s, token, csrf, fresh, "")
	_, stale, _ := callRoute(t, s, token, csrf, "/v1/account/chat-session/commit", map[string]string{"intent_id": old, "account_id": routeOwner, "alias": "alice"})
	if stale.Success || stale.ErrorCode != "chat_session_superseded" {
		t.Fatal("old commit changed the new login")
	}
	_, retry, _ := callRoute(t, s, token, csrf, "/v1/account/chat-session/prepare", map[string]string{"intent_id": old, "predecessor_generation": ""})
	if retry.Success {
		t.Fatal("old prepare rebased itself")
	}
	state, err := keychain.ReadChatLogin(s.app.Store)
	if err != nil || state.Generation != generation {
		t.Fatal("new generation changed")
	}
}

func TestOutOfOrderAndEqualChatClaimsCannotRebind(t *testing.T) {
	s := newTestServer(t)
	keys := routeKeypair(t)
	_ = keychain.SavePublicKey(s.app.Store, keys.PublicKey)
	one, csrf1 := openTestSession(t, s)
	two, csrf2 := openTestSession(t, s)
	generation := loginForFence(t, s, one, csrf1, "AAAAAAAAAAAAAAAAAAAAAA", "")
	claim := func(token, csrf string, sequence int) routeResult {
		return callFencedRoute(t, s, token, csrf, generation, "", "/v1/chat/runtime/claim", map[string]any{"holder_id": routeHolder, "sequence": sequence})
	}
	current := claim(two, csrf2, 2)
	if !current.Success {
		t.Fatal("new claim failed")
	}
	for _, stale := range []routeResult{claim(one, csrf1, 1), claim(one, csrf1, 2)} {
		if stale.Success || stale.ErrorCode != "chat_runtime_claim_stale" {
			t.Fatal("old/equal claim rebound the lease")
		}
	}
	var grant struct {
		Epoch string `json:"epoch"`
	}
	_ = json.Unmarshal(current.Data, &grant)
	admitted := callFencedRoute(t, s, two, csrf2, generation, grant.Epoch, "/v1/chat/mls_leaf_abort", map[string]any{})
	if !leaseAdmitted(proto.BaseResponse{Success: admitted.Success, ErrorCode: admitted.ErrorCode}) {
		t.Fatal("new holder lost authority")
	}
	if !claim(two, csrf2, 4).Success || claim(two, csrf2, 3).Success {
		t.Fatal("same-session reverse delivery was not fenced")
	}
}

func TestOldLoginPurgeCannotRevokeANewerLogin(t *testing.T) {
	s := newTestServer(t)
	keys := routeKeypair(t)
	_ = keychain.SavePublicKey(s.app.Store, keys.PublicKey)
	token, csrf := openTestSession(t, s)
	old := loginForFence(t, s, token, csrf, "AAAAAAAAAAAAAAAAAAAAAA", "")
	current := loginForFence(t, s, token, csrf, "BBBBBBBBBBBBBBBBBBBBBB", old)
	grant := callFencedRoute(t, s, token, csrf, current, "", "/v1/chat/runtime/claim", map[string]any{"holder_id": routeHolder, "sequence": 1})
	if !grant.Success {
		t.Fatal("new login claim failed")
	}
	var data struct {
		Epoch string `json:"epoch"`
	}
	_ = json.Unmarshal(grant.Data, &data)
	stale := callFencedRoute(t, s, token, csrf, old, data.Epoch, "/v1/chat/chat_state_purge", map[string]string{"owner_account_id": routeOwner, "expected_generation": old})
	if stale.Success || stale.ErrorCode != "chat_session_binding_required" {
		t.Fatal("old login purge was admitted")
	}
	admitted := callFencedRoute(t, s, token, csrf, current, data.Epoch, "/v1/chat/mls_leaf_abort", map[string]any{})
	if !leaseAdmitted(proto.BaseResponse{Success: admitted.Success, ErrorCode: admitted.ErrorCode}) {
		t.Fatal("old purge revoked the new login")
	}
}

func TestSequentialChatHoldersRemainRecoverable(t *testing.T) {
	s := newTestServer(t)
	keys := routeKeypair(t)
	_ = keychain.SavePublicKey(s.app.Store, keys.PublicKey)
	token, csrf := openTestSession(t, s)
	generation := loginForFence(t, s, token, csrf, "AAAAAAAAAAAAAAAAAAAAAA", "")
	for i := 0; i < 17; i++ {
		holder := fmt.Sprintf("holder-sequential-%022d", i)
		answer := callFencedRoute(t, s, token, csrf, generation, "", "/v1/chat/runtime/claim", map[string]any{"holder_id": holder, "sequence": 1})
		if !answer.Success {
			t.Fatalf("new sequential holder %d was refused: %s", i+1, answer.ErrorCode)
		}
		var grant struct {
			LeaseID string `json:"lease_id"`
		}
		if err := json.Unmarshal(answer.Data, &grant); err != nil {
			t.Fatal("invalid grant")
		}
		released := callFencedRoute(t, s, token, csrf, generation, "", "/v1/chat/runtime/release", map[string]any{"holder_id": holder, "lease_id": grant.LeaseID})
		if !released.Success {
			t.Fatal("holder release failed")
		}
	}
}
