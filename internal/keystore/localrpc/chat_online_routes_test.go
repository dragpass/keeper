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

const (
	onlineRouteAccount = "a1111111-1111-4111-8111-111111111111"
	onlineRouteDevice  = "d4444444-4444-4444-8444-444444444444"
	onlineRouteToken   = "e5555555-5555-4555-8555-555555555555"
	onlineRouteOrg     = "b2222222-2222-4222-8222-222222222222"
	onlineRouteConv    = "c3333333-3333-4333-8333-333333333333"
)

// lv78 K3/K4 at the App surface: the protected action's own route refuses
// without a decision, and prepare then execute with the API's decision
// reaches the action's handler.
func TestChatOnlineRoutesPrepareThenExecuteReachTheAction(t *testing.T) {
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

	request, _ := json.Marshal(map[string]any{
		"permit": map[string]any{
			"account_id": onlineRouteAccount, "org_id": onlineRouteOrg, "conversation_id": onlineRouteConv,
			"issued_at": 1, "expires_at": 301, "server_key_version": 1, "signature": "AA==",
		},
		"org_id": onlineRouteOrg, "conversation_id": onlineRouteConv,
		"client_message_id": "m-1", "expected_epoch": 1, "plaintext_b64": "aGk=",
	})

	_, direct, _ := callRoute(t, server, session, csrf, "/v1/chat/mls_encrypt", json.RawMessage(request))
	if direct.Success || direct.ErrorCode != "chat_online_decision_required" {
		t.Fatalf("direct protected route: %+v", direct)
	}

	code, prepared, body := callRoute(t, server, session, csrf, "/v1/chat/online/prepare", map[string]any{
		"action": "mls_encrypt", "request": json.RawMessage(request),
		"token_id": onlineRouteToken, "session_issued_at_nanos": "1788998000123456789",
	})
	if code != http.StatusOK || !prepared.Success {
		t.Fatalf("prepare: %d %s", code, body)
	}
	var challenge proto.ChatOnlinePrepareResponseData
	raw, _ := json.Marshal(prepared.Data)
	if err := json.Unmarshal(raw, &challenge); err != nil || challenge.Challenge == "" {
		t.Fatalf("prepare data: %s", raw)
	}
	now := clock.Now().Unix()
	decision := proto.ChatOnlineDecision{
		Challenge: challenge.Challenge, AccountID: onlineRouteAccount, DeviceID: onlineRouteDevice,
		TokenID: onlineRouteToken, SessionIssuedAtNanos: 1788998000123456789, Action: "mls_encrypt",
		OrgID: onlineRouteOrg, ConversationID: onlineRouteConv, RequestCommitment: challenge.RequestCommitment,
		IssuedAt: now, ExpiresAt: now + 10, ServerKeyVersion: 1,
	}
	sum := sha256.Sum256([]byte(proto.ChatOnlineDecisionCanonical(decision)))
	sig, err := rsa.SignPSS(rand.Reader, key, crypto.SHA256, sum[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256})
	if err != nil {
		t.Fatal(err)
	}
	decision.Signature = base64.StdEncoding.EncodeToString(sig)

	code, executed, body := callRoute(t, server, session, csrf, "/v1/chat/online/execute", map[string]any{
		"action": "mls_encrypt", "request": json.RawMessage(request), "decision": decision,
	})
	if code != http.StatusOK || executed.Success || !strings.HasPrefix(executed.ErrorCode, "CHAT_STATE_") {
		t.Fatalf("execute did not reach the handler: %d %s", code, body)
	}
	code, replay, _ := callRoute(t, server, session, csrf, "/v1/chat/online/execute", map[string]any{
		"action": "mls_encrypt", "request": json.RawMessage(request), "decision": decision,
	})
	if code != http.StatusOK || replay.ErrorCode != "chat_online_decision_refused" {
		t.Fatalf("replayed decision: %d %+v", code, replay)
	}
}

// The online routes carry any protected action's request, so they apply the
// action's own cap: the online path takes nothing its direct route refused.
func TestChatOnlineRoutesApplyTheActionsOwnCap(t *testing.T) {
	server, _ := newChatTestServer(t)
	session, csrf := openTestSession(t, server)
	claimLease(t, server, session, csrf, routeHolder)
	oversized, _ := json.Marshal(map[string]any{"plaintext_b64": strings.Repeat("A", proto.ChatStateMaxRequestBytes)})
	for _, path := range []string{"/v1/chat/online/prepare", "/v1/chat/online/execute"} {
		code, result, body := callRoute(t, server, session, csrf, path, map[string]any{
			"action": "mls_encrypt", "request": json.RawMessage(oversized),
		})
		if code != http.StatusBadRequest {
			t.Fatalf("%s took an mls_encrypt request past its cap: %d %+v %.120s", path, code, result, body)
		}
	}
}
