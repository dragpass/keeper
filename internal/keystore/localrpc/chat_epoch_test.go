package localrpc

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dragpass/keeper/internal/keystore"
)

func epochOf(data json.RawMessage) string {
	var decoded struct {
		Epoch string `json:"epoch"`
	}
	_ = json.Unmarshal(data, &decoded)
	return decoded.Epoch
}

func reasonOf(data json.RawMessage) string {
	var decoded struct {
		Reason string `json:"reason"`
	}
	_ = json.Unmarshal(data, &decoded)
	return decoded.Reason
}

// callWithEpoch is callRoute with an explicit epoch header ("" for none).
func callWithEpoch(t *testing.T, server *Server, session, csrf, path string, body any, epoch string) (int, routeResult) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	response := sessionRequestWithEpoch(server, http.MethodPost, path, string(raw), session, csrf, testOrigin, true, epoch)
	var result routeResult
	if response.Code == http.StatusOK {
		if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
			t.Fatalf("%s answer: %v", path, err)
		}
	}
	return response.Code, result
}

const extensionPurgeFrame = `{"action":"chat_state_purge","request_id":"ext-purge","payload":{"owner_account_id":"a1111111-1111-4111-8111-111111111111"}}`

func TestChatRuntimeClaimRouteGrantsAnEpochAndRefusesAStaleOne(t *testing.T) {
	server, _ := newChatTestServer(t)
	session, csrf := openTestSession(t, server)
	granted := claimLease(t, server, session, csrf, routeHolder)
	epoch := epochOf(granted.Data)
	if !granted.Success || epoch == "" {
		t.Fatalf("claim: %+v %s", granted, granted.Data)
	}
	code, renewed := callWithEpoch(t, server, session, csrf, "/v1/chat/runtime/claim", map[string]string{"holder_id": routeHolder, "epoch": epoch}, "")
	if code != http.StatusOK || !renewed.Success || epochOf(renewed.Data) != epoch {
		t.Fatalf("renew with the held epoch: %d %+v", code, renewed)
	}
	code, stale := callWithEpoch(t, server, session, csrf, "/v1/chat/runtime/claim", map[string]string{"holder_id": routeHolder, "epoch": "stale.0"}, "")
	if code != http.StatusOK || stale.Success || stale.ErrorCode != keystore.ErrCodeChatRuntimeRevoked {
		t.Fatalf("claim with a stale epoch: %d %+v", code, stale)
	}
	if code, _ := callWithEpoch(t, server, session, csrf, "/v1/chat/runtime/release", map[string]string{"holder_id": routeHolder, "epoch": epoch}, ""); code != http.StatusBadRequest {
		t.Fatalf("release took an epoch field: %d", code)
	}
}

func TestChatActionRoutesNeedTheEpochHeader(t *testing.T) {
	server, _ := newChatTestServer(t)
	session, csrf := openTestSession(t, server)
	epoch := epochOf(claimLease(t, server, session, csrf, routeHolder).Data)
	if _, result := callWithEpoch(t, server, session, csrf, "/v1/chat/mls_leaf_abort", map[string]any{}, ""); result.ErrorCode != keystore.ErrCodeChatRuntimeLeaseRequired {
		t.Fatalf("gated route without the epoch header: %+v", result)
	}
	if _, result := callWithEpoch(t, server, session, csrf, "/v1/chat/mls_leaf_abort", map[string]any{}, epoch); !result.Success {
		t.Fatalf("gated route with the epoch header: %+v", result)
	}
	for _, bad := range []string{"no-dot", strings.Repeat("a", 60) + ".12345", "a b.1", "abc.x"} {
		if code, _ := callWithEpoch(t, server, session, csrf, "/v1/chat/mls_leaf_abort", map[string]any{}, bad); code != http.StatusBadRequest {
			t.Fatalf("malformed epoch %q: %d", bad, code)
		}
	}
}

// The Extension logs out while the App holds the lease: the purge runs, and
// every later call of the old runtime is refused as revoked, not busy.
func TestExtensionPurgeRevokesTheAppRuntimeOverLocalRPC(t *testing.T) {
	server, _ := newChatTestServer(t)
	session, csrf := openTestSession(t, server)
	epoch := epochOf(claimLease(t, server, session, csrf, routeHolder).Data)

	if purged := proxiedFrame(t, server, extensionPurgeFrame); !purged.Success {
		t.Fatalf("Extension purge while the App holds the lease: %+v", purged)
	}
	for _, path := range []string{"/v1/chat/mls_leaf_abort", "/v1/chat/mls_mark_sent", "/v1/chat/chat_state_purge"} {
		_, result := callWithEpoch(t, server, session, csrf, path, map[string]any{}, epoch)
		if result.ErrorCode != keystore.ErrCodeChatRuntimeRevoked || reasonOf(result.Data) != keystore.ChatRuntimeRevokedPurged {
			t.Fatalf("%s after the purge: %+v", path, result)
		}
	}
	_, reclaim := callWithEpoch(t, server, session, csrf, "/v1/chat/runtime/claim", map[string]string{"holder_id": routeHolder, "epoch": epoch}, "")
	if reclaim.ErrorCode != keystore.ErrCodeChatRuntimeRevoked {
		t.Fatalf("reclaim with the revoked epoch: %+v", reclaim)
	}
	if _, result := signChatWrite(t, server, session, csrf, "POST", "/api/v1/conversations/"+routeOwner+"/messages", epoch); result.ErrorCode != keystore.ErrCodeChatRuntimeRevoked {
		t.Fatalf("signing a message send after the purge: %+v", result)
	}
}

func signChatWrite(t *testing.T, server *Server, session, csrf, method, path, epoch string) (int, routeResult) {
	t.Helper()
	body := map[string]string{
		"method": method, "path": path, "query": "",
		"timestamp": fmt.Sprint(server.now().Unix()), "nonce": randomNonceForTest(t),
		"body_sha256": strings.Repeat("0", 64),
		"account_id":  "11111111-1111-4111-8111-111111111111",
		"token_id":    "22222222-2222-4222-8222-222222222222", "device_id": "device-12345678",
	}
	return callWithEpoch(t, server, session, csrf, "/v1/request-signature", body, epoch)
}

func randomNonceForTest(t *testing.T) string {
	t.Helper()
	token, err := randomToken()
	if err != nil {
		t.Fatal(err)
	}
	return token[:22]
}

// A chat write is signed only for the lease holder at the current epoch;
// every other request is signed as before.
func TestRequestSignatureFencesChatWrites(t *testing.T) {
	server, _ := newChatTestServer(t)
	if response := server.app.HandleRequest([]byte(`{"action":"request_key_generate"}`)); !response.Success {
		t.Fatalf("request key generation failed: %+v", response)
	}
	session, csrf := openTestSession(t, server)
	conversation := "/api/v1/conversations/" + routeOwner
	writes := [][2]string{
		{"POST", conversation + "/messages"}, {"POST", conversation + "/mls/commit"},
		{"POST", conversation + "/leave"}, {"PUT", conversation + "/mls/name"},
		{"DELETE", conversation}, {"POST", "/api/v1/conversations/rooms"}, {"POST", "/api/v1/chat/anything"},
	}
	free := [][2]string{
		{"GET", conversation + "/messages"}, {"POST", conversation + "/state-permit"},
		{"POST", "/api/v1/account/devices"}, {"GET", "/api/v1/conversations"},
	}
	for _, write := range writes {
		if code, result := signChatWrite(t, server, session, csrf, write[0], write[1], ""); code != http.StatusOK || result.ErrorCode != keystore.ErrCodeChatRuntimeLeaseRequired {
			t.Fatalf("%v without a lease: %d %+v", write, code, result)
		}
	}
	for _, request := range free {
		if code, result := signChatWrite(t, server, session, csrf, request[0], request[1], ""); code != http.StatusOK || !result.Success {
			t.Fatalf("%v without a lease: %d %+v", request, code, result)
		}
	}
	epoch := epochOf(claimLease(t, server, session, csrf, routeHolder).Data)
	for _, write := range writes {
		if code, result := signChatWrite(t, server, session, csrf, write[0], write[1], epoch); code != http.StatusOK || !result.Success {
			t.Fatalf("%v with the lease: %d %+v", write, code, result)
		}
	}
	other, otherCSRF := openTestSession(t, server)
	if _, result := signChatWrite(t, server, other, otherCSRF, "POST", conversation+"/messages", epoch); result.ErrorCode != keystore.ErrCodeChatRuntimeLeaseRequired {
		t.Fatalf("another session signing with the holder's epoch: %+v", result)
	}
}

func TestPreflightAllowsTheEpochHeader(t *testing.T) {
	server := newTestServer(t)
	request := httptest.NewRequest(http.MethodOptions, "http://"+server.host+"/v1/chat/mls_encrypt", nil)
	request.Host = server.host
	request.RemoteAddr = "127.0.0.1:54321"
	request.Header.Set("Origin", testOrigin)
	request.Header.Set("Sec-Fetch-Site", "cross-site")
	request.Header.Set("Access-Control-Request-Method", "POST")
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if !strings.Contains(recorder.Header().Get("Access-Control-Allow-Headers"), chatRuntimeEpochHeader) {
		t.Fatalf("preflight headers: %v", recorder.Header())
	}
}
