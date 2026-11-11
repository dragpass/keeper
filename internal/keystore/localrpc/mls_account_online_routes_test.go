package localrpc

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"strings"
	"testing"

	"github.com/dragpass/keeper/config"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// lv78 A1b at the App surface: an account-level action's own route refuses
// without a decision, and prepare then execute with the API's account
// decision reaches the action's handler, once.
func TestAccountOnlineRoutesPrepareThenExecuteReachTheAction(t *testing.T) {
	server, clock := newChatTestServer(t)
	store := server.app.Store
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err := keychain.SaveServerPublicKeyForVersion(store, 1, string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))); err != nil {
		t.Fatal(err)
	}
	if err := store.Set(config.Service, config.DeviceID, onlineRouteDevice); err != nil {
		t.Fatal(err)
	}
	if _, _, err := keychain.SetAccountBinding(store, onlineRouteAccount, "alice", true); err != nil {
		t.Fatal(err)
	}
	session, csrf := openTestSession(t, server)
	claimLease(t, server, session, csrf, routeHolder)

	revoked := "d7777777-4444-4444-8444-444444444444"
	request, _ := json.Marshal(map[string]any{"account_id": onlineRouteAccount, "device_id": revoked})

	_, direct, _ := callRoute(t, server, session, csrf, "/v1/chat/mls_device_revoke_sign", json.RawMessage(request))
	if direct.Success || direct.ErrorCode != "chat_online_decision_required" {
		t.Fatalf("direct account route: %+v", direct)
	}

	code, prepared, body := callRoute(t, server, session, csrf, "/v1/chat/account-online/prepare", map[string]any{
		"action": "mls_device_revoke_sign", "request": json.RawMessage(request),
		"token_id": onlineRouteToken, "session_issued_at_nanos": "1788998000123456789",
	})
	if code != http.StatusOK || !prepared.Success {
		t.Fatalf("prepare: %d %s", code, body)
	}
	var challenge proto.MLSAccountOnlinePrepareResponseData
	raw, _ := json.Marshal(prepared.Data)
	if err := json.Unmarshal(raw, &challenge); err != nil || challenge.Challenge == "" || challenge.Target != "device:"+revoked {
		t.Fatalf("prepare data: %s", raw)
	}
	now := clock.Now().Unix()
	decision := proto.MLSAccountOnlineDecision{
		Challenge: challenge.Challenge, AccountID: onlineRouteAccount, DeviceID: onlineRouteDevice,
		TokenID: onlineRouteToken, SessionIssuedAtNanos: 1788998000123456789, Action: "mls_device_revoke_sign",
		Target: challenge.Target, RequestCommitment: challenge.RequestCommitment,
		IssuedAt: now, ExpiresAt: now + 10, ServerKeyVersion: 1,
	}
	sum := sha256.Sum256([]byte(proto.MLSAccountOnlineDecisionCanonical(decision)))
	sig, err := rsa.SignPSS(rand.Reader, key, crypto.SHA256, sum[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256})
	if err != nil {
		t.Fatal(err)
	}
	decision.Signature = base64.StdEncoding.EncodeToString(sig)

	// The chat path does not take it.
	code, crossed, _ := callRoute(t, server, session, csrf, "/v1/chat/online/execute", map[string]any{
		"action": "mls_device_revoke_sign", "request": json.RawMessage(request), "decision": decision,
	})
	if code == http.StatusOK && crossed.Success {
		t.Fatalf("the chat execute route ran an account action: %+v", crossed)
	}

	code, executed, body := callRoute(t, server, session, csrf, "/v1/chat/account-online/execute", map[string]any{
		"action": "mls_device_revoke_sign", "request": json.RawMessage(request), "decision": decision,
	})
	// No leaf key in this Keeper: the handler's own refusal shows the gate
	// admitted the call.
	if code != http.StatusOK || executed.Success || executed.ErrorCode != "CHAT_MLS_FAILED" {
		t.Fatalf("execute did not reach the handler: %d %s", code, body)
	}
	code, replay, _ := callRoute(t, server, session, csrf, "/v1/chat/account-online/execute", map[string]any{
		"action": "mls_device_revoke_sign", "request": json.RawMessage(request), "decision": decision,
	})
	if code != http.StatusOK || replay.ErrorCode != "chat_online_decision_refused" {
		t.Fatalf("replayed decision: %d %+v", code, replay)
	}
}

// The account routes take only an account-level action, with its own strict
// decode and cap.
func TestAccountOnlineRoutesTakeOnlyAnAccountActionsOwnRequest(t *testing.T) {
	server, _ := newChatTestServer(t)
	session, csrf := openTestSession(t, server)
	claimLease(t, server, session, csrf, routeHolder)
	for name, body := range map[string]map[string]any{
		"a chat action":     {"action": "mls_encrypt", "request": json.RawMessage(`{}`)},
		"an unknown field":  {"action": "mls_leaf_promote", "request": json.RawMessage(`{"acceptance_token":"t","server_signature":"AA==","extra":1}`)},
		"an oversized body": {"action": "mls_leaf_promote", "request": json.RawMessage(`{"acceptance_token":"` + strings.Repeat("A", proto.ChatStateMaxRequestBytes) + `"}`)},
	} {
		for _, path := range []string{"/v1/chat/account-online/prepare", "/v1/chat/account-online/execute"} {
			t.Run(name+" "+path, func(t *testing.T) {
				code, result, raw := callRoute(t, server, session, csrf, path, body)
				if code != http.StatusBadRequest {
					t.Fatalf("%d %+v %.120s", code, result, raw)
				}
			})
		}
	}
}
