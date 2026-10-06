package localrpc

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dragpass/keeper/internal/keystore"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/localsecret"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/testdouble"
)

const (
	routeHolder      = "YXBwLXRhYi1ob2xkZXItMDE"
	routeOtherHolder = "YXBwLXRhYi1ob2xkZXItMDI"
	// leafAbortFrame is a lease-gated action that succeeds on an empty keyring.
	leafAbortFrame = `{"action":"mls_leaf_abort","request_id":"ext-1","payload":{}}`
)

type mutableClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *mutableClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *mutableClock) advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

// newChatTestServer gives the lease its own controllable clock.
func newChatTestServer(t *testing.T) (*Server, *mutableClock) {
	t.Helper()
	server := newTestServer(t)
	clock := &mutableClock{now: time.Unix(1_800_000_000, 0)}
	server.app.Clock = clock.Now
	return server, clock
}

// proxiedFrame sends one Native Messaging frame the way a proxy host does. It
// reports with t.Errorf so a race test may call it from a goroutine.
func proxiedFrame(t *testing.T, server *Server, frame string) proto.BaseResponse {
	t.Helper()
	body, nonce, err := sealProxyRequest(server.proxy.currentKey(), server.proxy.instance, server.now(), []byte(frame))
	if err != nil {
		t.Fatal(err)
	}
	response := localRequestFromOrigin(server, http.MethodPost, "/v1/native-proxy/message", string(body), "", "", NativeExtensionOrigin)
	var result proto.BaseResponse
	if response.Code != http.StatusOK {
		t.Errorf("proxied frame: %d %s", response.Code, response.Body.String())
		return result
	}
	plain, err := openProxyResponse(server.proxy.currentKey(), server.proxy.instance, nonce, response.Body.Bytes())
	if err != nil || json.Unmarshal(plain, &result) != nil {
		t.Errorf("proxied answer does not open: %v", err)
	}
	return result
}

func holderOf(t *testing.T, data any) string {
	t.Helper()
	raw, _ := json.Marshal(data)
	var decoded struct {
		Holder string `json:"holder"`
	}
	_ = json.Unmarshal(raw, &decoded)
	return decoded.Holder
}

func claimLease(t *testing.T, server *Server, session, csrf, holder string) routeResult {
	t.Helper()
	code, result, body := callRoute(t, server, session, csrf, "/v1/chat/runtime/claim", map[string]string{"holder_id": holder})
	if code != http.StatusOK {
		t.Errorf("claim: %d %s", code, body)
	}
	if epoch := epochOf(result.Data); result.Success && epoch != "" {
		sessionEpochs.Store(session, epoch)
	}
	return result
}

// Every path the App can reach through appRoutes. A new route must be added
// here on purpose.
var pinnedAppRoutes = []string{
	"/v1/account-key/public",
	"/v1/account-key/rotate/abort",
	"/v1/account-key/rotate/prepare",
	"/v1/account-key/rotate/promote",
	"/v1/account-key/rotate/rewrap-group-dek",
	"/v1/account-key/rotate/status",
	"/v1/account/binding",
	"/v1/archive/account_archive_key_generate",
	"/v1/archive/account_archive_key_status",
	"/v1/archive/archive_key_generate",
	"/v1/archive/archive_key_rotate_abort",
	"/v1/archive/archive_key_rotate_begin",
	"/v1/archive/archive_key_rotate_commit",
	"/v1/archive/archive_key_split",
	"/v1/archive/archive_key_status",
	"/v1/archive/archive_quorum_combine_and_rewrap",
	"/v1/archive/archive_session_begin",
	"/v1/archive/archive_session_end",
	"/v1/archive/archive_share_rewrap",
	"/v1/archive/archive_unwrap_and_rewrap",
	"/v1/auth/password/rewrap",
	"/v1/auth/recovery/abort",
	"/v1/auth/recovery/begin",
	"/v1/auth/recovery/close",
	"/v1/auth/recovery/prepare",
	"/v1/auth/recovery/rewrap-group-dek",
	"/v1/auth/signup/abort",
	"/v1/chat/capability",
	"/v1/chat/chat_state_purge",
	"/v1/chat/chat_state_read_outbox",
	"/v1/chat/mls_commit_build",
	"/v1/chat/mls_commit_confirm",
	"/v1/chat/mls_conversation_forget_removed",
	"/v1/chat/mls_conversation_status",
	"/v1/chat/mls_decrypt_batch_for_app_display",
	"/v1/chat/mls_device_revoke_sign",
	"/v1/chat/mls_encrypt",
	"/v1/chat/mls_epoch_comparison",
	"/v1/chat/mls_group_create",
	"/v1/chat/mls_group_discard_unaccepted",
	"/v1/chat/mls_join",
	"/v1/chat/mls_key_package_generate",
	"/v1/chat/mls_leaf_abort",
	"/v1/chat/mls_leaf_declare",
	"/v1/chat/mls_leaf_handover_sign",
	"/v1/chat/mls_leaf_promote",
	"/v1/chat/mls_leaf_status",
	"/v1/chat/mls_leave_request_sign",
	"/v1/chat/mls_mark_sent",
	"/v1/chat/mls_process",
	"/v1/chat/mls_rejoin_request_sign",
	"/v1/chat/mls_room_name_open",
	"/v1/chat/mls_room_name_seal",
	"/v1/chat/org_member_removal_sign",
	"/v1/chat/room_row_name_seal",
	"/v1/chat/runtime/claim",
	"/v1/chat/runtime/release",
	"/v1/device/forget",
	"/v1/device/id",
	"/v1/device/signout",
	"/v1/device/status",
	"/v1/group-dek/close",
	"/v1/group-dek/generate",
	"/v1/group-dek/open",
	"/v1/group-dek/rewrap-for-many",
	"/v1/group-dek/rewrap-for-member",
	"/v1/guest-share/transcrypt",
	"/v1/key-transparency/monitor",
	"/v1/key-transparency/status",
	"/v1/message/display",
	"/v1/message/display-prepare",
	"/v1/message/seal",
	"/v1/peer-key/chain-evaluate",
	"/v1/peer-key/pin",
	"/v1/peer-key/pin-list",
	"/v1/peer-key/pin-verify",
	"/v1/peer-key/policy-get",
	"/v1/peer-key/policy-set",
	"/v1/peer-key/safety-number",
}

func TestAppRouteAllowlistIsPinned(t *testing.T) {
	got := make([]string, 0, len(appRoutes))
	for path := range appRoutes {
		got = append(got, path)
	}
	sort.Strings(got)
	if strings.Join(got, "\n") != strings.Join(pinnedAppRoutes, "\n") {
		t.Fatalf("App routes changed:\n%s", strings.Join(got, "\n"))
	}
}

// The only App routes that answer plaintext are the chat display actions and
// the secure message display, all carved out of the no-raw-secret rule. The
// one encrypt route seals under the message AAD it builds itself.
func TestAppRoutesAddNoPlaintextAnswer(t *testing.T) {
	plaintextActions := map[string]bool{
		proto.MLSDecryptBatchForAppDisplay: true,
		proto.MLSRoomNameOpen:              true,
	}
	carvedOut := map[string]string{
		"/v1/message/display": proto.ActionGroupDecryptWithAadForAppDisplay,
		"/v1/message/seal":    proto.ActionGroupEncryptWithAAD,
	}
	if appRoutes["/v1/message/seal"].bind == nil {
		t.Fatal("/v1/message/seal must build its AAD, not take one")
	}
	for path, route := range appRoutes {
		if plaintextActions[route.action] && path != "/v1/chat/"+route.action {
			t.Fatalf("%s reaches a plaintext action", path)
		}
		if carvedOut[path] == route.action {
			continue
		}
		switch route.action {
		case proto.ActionGroupDecryptToClipboard, proto.ActionGroupDecryptWithAadForAppDisplay,
			proto.ActionGroupEncrypt, proto.ActionGroupEncryptWithAAD:
			t.Fatalf("%s exposes %s", path, route.action)
		}
	}
}

func TestChatCapabilityReturnsPingMetadataWithoutALease(t *testing.T) {
	server, _ := newChatTestServer(t)
	session, csrf := openTestSession(t, server)
	code, result, body := callRoute(t, server, session, csrf, "/v1/chat/capability", map[string]any{})
	if code != http.StatusOK || !result.Success {
		t.Fatalf("capability: %d %s", code, body)
	}
	var data map[string]json.RawMessage
	_ = json.Unmarshal(result.Data, &data)
	var contract int
	_ = json.Unmarshal(data["chat_contract"], &contract)
	if contract != proto.ChatContract || data["chat_capabilities"] == nil || data["version"] == nil {
		t.Fatalf("capability data: %s", result.Data)
	}
	if _, ok := data["path"]; ok {
		t.Fatalf("capability reveals the binary path: %s", result.Data)
	}
	if code, _, _ := callRoute(t, server, session, csrf, "/v1/chat/capability", map[string]any{"x": 1}); code != http.StatusBadRequest {
		t.Fatalf("capability took an unknown field: %d", code)
	}
}

func TestChatRuntimeClaimAndReleaseRoutes(t *testing.T) {
	server, _ := newChatTestServer(t)
	first, firstCSRF := openTestSession(t, server)
	second, secondCSRF := openTestSession(t, server)

	result := claimLease(t, server, first, firstCSRF, routeHolder)
	var granted struct {
		ExpiresAt  int64 `json:"expires_at"`
		TTLSeconds int   `json:"ttl_seconds"`
	}
	_ = json.Unmarshal(result.Data, &granted)
	if !result.Success || granted.TTLSeconds != 60 || granted.ExpiresAt != server.app.Clock().Add(60*time.Second).Unix() {
		t.Fatalf("claim: %+v %s", result, result.Data)
	}
	busy := claimLease(t, server, second, secondCSRF, routeOtherHolder)
	if busy.Success || busy.ErrorCode != "chat_runtime_busy" || !strings.Contains(string(busy.Data), `"holder":"app"`) {
		t.Fatalf("another holder: %+v %s", busy, busy.Data)
	}
	for _, bad := range []any{
		map[string]string{"holder_id": "short"},
		map[string]string{"holder_id": strings.Repeat("a", 65)},
		map[string]string{"holder_id": "has space in it but is long enough"},
		map[string]string{"holder_id": "padded+base64/value=========="},
		map[string]any{"holder_id": routeHolder, "session": first},
		map[string]any{},
	} {
		if code, _, _ := callRoute(t, server, first, firstCSRF, "/v1/chat/runtime/claim", bad); code != http.StatusBadRequest {
			t.Fatalf("claim with %v: %d", bad, code)
		}
	}

	code, released, _ := callRoute(t, server, second, secondCSRF, "/v1/chat/runtime/release", map[string]string{"holder_id": routeOtherHolder})
	if code != http.StatusOK || !released.Success || string(released.Data) != `{"released":false}` {
		t.Fatalf("release by another holder: %d %+v", code, released)
	}
	code, released, _ = callRoute(t, server, first, firstCSRF, "/v1/chat/runtime/release", map[string]string{"holder_id": routeHolder})
	if code != http.StatusOK || string(released.Data) != `{"released":true}` {
		t.Fatalf("release: %d %s", code, released.Data)
	}
	if result := claimLease(t, server, second, secondCSRF, routeOtherHolder); !result.Success {
		t.Fatalf("claim after release: %+v", result)
	}
}

func TestChatRuntimeLeaseGatesTheExtensionAndDiesWithItsSession(t *testing.T) {
	server, clock := newChatTestServer(t)
	session, csrf := openTestSession(t, server)
	claimLease(t, server, session, csrf, routeHolder)

	refused := proxiedFrame(t, server, leafAbortFrame)
	if refused.Success || refused.ErrorCode != "chat_runtime_busy" || holderOf(t, refused.Data) != "app" || refused.RequestID != "ext-1" {
		t.Fatalf("proxied gated frame while the App holds the lease: %+v", refused)
	}
	if ping := proxiedFrame(t, server, `{"action":"ping"}`); !ping.Success {
		t.Fatalf("proxied ping: %+v", ping)
	}

	// Closing the session drops the lease.
	if got := localRequest(server, http.MethodDelete, "/v1/session", "", session, csrf).Code; got != http.StatusNoContent {
		t.Fatalf("close session: %d", got)
	}
	if ran := proxiedFrame(t, server, leafAbortFrame); !ran.Success {
		t.Fatalf("the lease outlived its session: %+v", ran)
	}

	// Extension activity now keeps the App out for the window.
	next, nextCSRF := openTestSession(t, server)
	if result := claimLease(t, server, next, nextCSRF, routeHolder); result.Success || !strings.Contains(string(result.Data), `"holder":"extension"`) {
		t.Fatalf("claim right after Extension activity: %+v %s", result, result.Data)
	}
	clock.advance(keystore.ChatRuntimeExtensionWindow)
	if result := claimLease(t, server, next, nextCSRF, routeHolder); !result.Success {
		t.Fatalf("claim after the window: %+v", result)
	}

	// Rotating the local secret drops every session and the lease with them.
	if _, err := localsecret.Rotate(); err != nil {
		t.Fatal(err)
	}
	if got := localRequest(server, http.MethodPost, "/v1/status", "{}", next, nextCSRF).Code; got != http.StatusUnauthorized {
		t.Fatalf("status after rotation: %d", got)
	}
	if ran := proxiedFrame(t, server, leafAbortFrame); !ran.Success {
		t.Fatalf("the lease outlived a secret rotation: %+v", ran)
	}
}

func TestChatRuntimeLeaseNeverOutlivesItsSession(t *testing.T) {
	server, _ := newChatTestServer(t)
	session, csrf := openTestSession(t, server)
	server.now = func() time.Time { return time.Unix(1_800_000_000, 0).Add(10*time.Minute - 20*time.Second) }
	result := claimLease(t, server, session, csrf, routeHolder)
	var granted struct {
		ExpiresAt int64 `json:"expires_at"`
	}
	_ = json.Unmarshal(result.Data, &granted)
	if !result.Success || granted.ExpiresAt != server.app.Clock().Add(20*time.Second).Unix() {
		t.Fatalf("claim near the end of the session: %+v %s", result, result.Data)
	}
}

func chatActionPaths() []string {
	var paths []string
	for path, route := range appRoutes {
		if strings.HasPrefix(path, "/v1/chat/") && path == "/v1/chat/"+route.action {
			paths = append(paths, path)
		}
	}
	sort.Strings(paths)
	return paths
}

func TestChatActionRoutesDecodeStrictlyAndAreGated(t *testing.T) {
	server, _ := newChatTestServer(t)
	session, csrf := openTestSession(t, server)
	paths := chatActionPaths()
	if len(paths) != 26 {
		t.Fatalf("chat action routes: %d %v", len(paths), paths)
	}
	gated := map[string]bool{}
	for _, action := range keystore.ChatRuntimeGatedActions() {
		gated[action] = true
	}
	for _, path := range paths {
		action := strings.TrimPrefix(path, "/v1/chat/")
		if code, _, _ := callRoute(t, server, session, csrf, path, map[string]any{"not_a_field": 1}); code != http.StatusBadRequest {
			t.Fatalf("%s took an unknown field: %d", path, code)
		}
		if got := localRequest(server, http.MethodPost, path, `{}{}`, session, csrf).Code; got != http.StatusBadRequest {
			t.Fatalf("%s took two objects: %d", path, got)
		}
		code, result, body := callRoute(t, server, session, csrf, path, map[string]any{})
		if code != http.StatusOK {
			t.Fatalf("%s: %d %s", path, code, body)
		}
		if gated[action] != (result.ErrorCode == "chat_runtime_lease_required") {
			t.Fatalf("%s without a lease: %+v", path, result)
		}
	}
	for _, missing := range []string{
		"/v1/chat/chat_state_reserve_send", "/v1/chat/chat_state_commit_outbox", "/v1/chat/chat_state_mark_received",
		"/v1/chat/group_encrypt_with_aad", "/v1/chat/group_decrypt", "/v1/chat/", "/v1/chat/runtime", "/v1/chat/MLS_ENCRYPT",
	} {
		if got := localRequest(server, http.MethodPost, missing, `{}`, session, csrf).Code; got != http.StatusNotFound {
			t.Fatalf("%s = %d, want 404", missing, got)
		}
	}
}

func TestChatActionRoutesRunWithTheLeaseAndKeepTheRawRequest(t *testing.T) {
	server, _ := newChatTestServer(t)
	session, csrf := openTestSession(t, server)
	claimLease(t, server, session, csrf, routeHolder)
	code, result, body := callRoute(t, server, session, csrf, "/v1/chat/mls_leaf_abort", map[string]any{})
	if code != http.StatusOK || !result.Success {
		t.Fatalf("leaf abort with the lease: %d %s", code, body)
	}
	// The route hands the handler the bytes it was sent, so the handler's
	// strict decoder still sees (and refuses) a duplicate key.
	duplicate := `{"org_id":"` + routeOwner + `","org_id":"` + routePeer + `"}`
	response := localRequest(server, http.MethodPost, "/v1/chat/mls_conversation_status", duplicate, session, csrf)
	var status routeResult
	_ = json.Unmarshal(response.Body.Bytes(), &status)
	if response.Code != http.StatusOK || status.Success || status.ErrorCode != string(errs.ErrCodeChatStateInvalidInput) || !strings.Contains(status.Error, "duplicate") {
		t.Fatalf("duplicate key: %d %s", response.Code, response.Body.String())
	}
}

func TestChatActionRoutesTakeTheirHandlersSizeCaps(t *testing.T) {
	server, _ := newChatTestServer(t)
	session, csrf := openTestSession(t, server)
	claimLease(t, server, session, csrf, routeHolder)
	batch := func(count int) map[string]any {
		messages := make([]map[string]any, count)
		for i := range messages {
			messages[i] = map[string]any{"seq": i + 1, "ciphertext_b64": strings.Repeat("A", 10_000)}
		}
		return map[string]any{"messages": messages}
	}
	code, result, body := callRoute(t, server, session, csrf, "/v1/chat/mls_decrypt_batch_for_app_display", batch(200))
	if code != http.StatusOK || result.ErrorCode != string(errs.ErrCodeChatStateInvalidInput) {
		t.Fatalf("a 2 MB display batch did not reach the handler: %d %.200s", code, body)
	}
	if code, _, _ := callRoute(t, server, session, csrf, "/v1/chat/mls_decrypt_batch_for_app_display", batch(320)); code != http.StatusBadRequest {
		t.Fatalf("a display batch past 3 MiB was accepted: %d", code)
	}
	if code, _, _ := callRoute(t, server, session, csrf, "/v1/chat/mls_encrypt", map[string]any{
		"plaintext_b64": strings.Repeat("A", proto.ChatStateMaxRequestBytes),
	}); code != http.StatusBadRequest {
		t.Fatalf("an mls_encrypt request past its cap was accepted: %d", code)
	}
	code, result, body = callRoute(t, server, session, csrf, "/v1/chat/mls_commit_build", map[string]any{
		"app_context_b64": strings.Repeat("A", 200_000),
	})
	if code != http.StatusOK || result.ErrorCode != string(errs.ErrCodeChatStateInvalidInput) {
		t.Fatalf("a 200 KB commit build did not reach the handler: %d %.200s", code, body)
	}
}

type observedAction struct {
	action   string
	payload  string
	response proto.BaseResponse
}

func observeActions(server *Server) *[]observedAction {
	var mu sync.Mutex
	seen := &[]observedAction{}
	server.onAction = func(action string, payload []byte, response proto.BaseResponse) {
		mu.Lock()
		*seen = append(*seen, observedAction{action, string(payload), response})
		mu.Unlock()
	}
	return seen
}

func TestRoomRowNameSealUsesAThrowawayKeyAndTheFixedAAD(t *testing.T) {
	server, _ := newChatTestServer(t)
	store := server.app.Store.(*testdouble.MemorySecretStore)
	own := routeKeypair(t)
	_ = keychain.SavePrivateKey(store, own.PrivateKey)
	_ = keychain.SavePublicKey(store, own.PublicKey)
	session, csrf := openTestSession(t, server)
	seen := observeActions(server)

	const org, conversation = "66666666-6666-4666-8666-666666666666", "77777777-7777-4777-8777-777777777777"
	name := []byte("설계 회의")
	code, result, body := callRoute(t, server, session, csrf, "/v1/chat/room_row_name_seal", map[string]string{
		"org_id": org, "conversation_id": conversation, "plaintext_b64": base64.StdEncoding.EncodeToString(name),
	})
	if code != http.StatusOK || !result.Success || strings.Contains(body, "encrypted_for_me") || strings.Contains(body, "group_handle") {
		t.Fatalf("seal: %d %s", code, body)
	}
	var sealed struct {
		IVB64         string `json:"iv_b64"`
		CiphertextB64 string `json:"ciphertext_b64"`
	}
	_ = json.Unmarshal(result.Data, &sealed)

	var actions []string
	var dek []byte
	for _, a := range *seen {
		actions = append(actions, a.action)
		if a.action == proto.ActionGroupDEKGenerateAndOpen {
			raw, _ := json.Marshal(a.response.Data)
			var generated proto.GroupDEKGenerateAndOpenResponseData
			_ = json.Unmarshal(raw, &generated)
			dek = openWith(t, own.PrivateKey, generated.EncryptedForMeB64)
		}
	}
	if strings.Join(actions, ",") != proto.ActionGetPublicKey+",group_dek_generate_and_open,group_encrypt_with_aad,group_session_close" {
		t.Fatalf("seal ran %v", actions)
	}
	if (*seen)[3].response.Success != true {
		t.Fatal("the throwaway handle was not closed")
	}
	block, _ := aes.NewCipher(dek)
	gcm, _ := cipher.NewGCM(block)
	iv, _ := base64.StdEncoding.DecodeString(sealed.IVB64)
	ciphertext, _ := base64.StdEncoding.DecodeString(sealed.CiphertextB64)
	opened, err := gcm.Open(nil, iv, ciphertext, []byte("dragpass.room|1|"+org+"|"+conversation+"|1"))
	if err != nil || !bytes.Equal(opened, name) {
		t.Fatalf("the name does not open under the fixed AAD: %v", err)
	}

	valid := map[string]string{"org_id": org, "conversation_id": conversation, "plaintext_b64": base64.StdEncoding.EncodeToString(name)}
	refusals := map[string]map[string]string{
		"an uppercase org id":      {"org_id": "AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE"},
		"a nil conversation id":    {"conversation_id": "00000000-0000-0000-0000-000000000000"},
		"a short conversation id":  {"conversation_id": conversation[:35]},
		"an empty name":            {"plaintext_b64": ""},
		"a name past 256 bytes":    {"plaintext_b64": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("a"), 257))},
		"a name that is not UTF-8": {"plaintext_b64": base64.StdEncoding.EncodeToString([]byte{0xff, 0xfe})},
		"a name that is not b64":   {"plaintext_b64": "not base64!"},
		"a caller-chosen AAD":      {"aad_b64": "eA=="},
		"a caller-chosen handle":   {"group_handle": "h"},
	}
	for name, change := range refusals {
		request := map[string]string{}
		for key, value := range valid {
			request[key] = value
		}
		for key, value := range change {
			request[key] = value
		}
		if code, _, _ := callRoute(t, server, session, csrf, "/v1/chat/room_row_name_seal", request); code != http.StatusBadRequest {
			t.Fatalf("seal with %s: %d", name, code)
		}
	}
}

func TestPeerKeyRoutesPassTheirTypedRequests(t *testing.T) {
	server, _ := newChatTestServer(t)
	session, csrf := openTestSession(t, server)
	peer := routeKeypair(t)

	code, result, body := callRoute(t, server, session, csrf, "/v1/peer-key/policy-set", map[string]bool{"require_verified_peers": true})
	if code != http.StatusOK || !result.Success {
		t.Fatalf("policy-set: %d %s", code, body)
	}
	code, result, _ = callRoute(t, server, session, csrf, "/v1/peer-key/policy-get", map[string]any{})
	if code != http.StatusOK || !strings.Contains(string(result.Data), `"require_verified_peers":true`) {
		t.Fatalf("policy-get: %d %s", code, result.Data)
	}
	if code, result, _ := callRoute(t, server, session, csrf, "/v1/peer-key/policy-set", map[string]any{}); code != http.StatusOK || result.Success {
		t.Fatalf("policy-set without a value: %d %+v", code, result)
	}
	code, result, body = callRoute(t, server, session, csrf, "/v1/peer-key/safety-number", map[string]string{
		"owner_account_id": routeOwner, "account_id": routePeer, "public_key": peer.PublicKey,
	})
	if code != http.StatusOK || (!result.Success && result.ErrorCode == "") {
		t.Fatalf("safety-number: %d %s", code, body)
	}
	for path, request := range map[string]any{
		"/v1/peer-key/pin-list":       map[string]string{"owner_account_id": routeOwner},
		"/v1/peer-key/pin-verify":     map[string]string{"owner_account_id": routeOwner, "account_id": routePeer, "fingerprint": "x", "public_key": peer.PublicKey},
		"/v1/peer-key/chain-evaluate": map[string]string{"owner_account_id": routeOwner, "account_id": routePeer, "public_key": peer.PublicKey},
	} {
		if code, _, body := callRoute(t, server, session, csrf, path, request); code != http.StatusOK {
			t.Fatalf("%s: %d %s", path, code, body)
		}
		withExtra := map[string]any{"unexpected": true}
		if code, _, _ := callRoute(t, server, session, csrf, path, withExtra); code != http.StatusBadRequest {
			t.Fatalf("%s took an unknown field: %d", path, code)
		}
	}
	// Forgetting a pin re-TOFUs a changed key; the key-trust UI dropped it
	// (MLS hardening policy Q9 (a)) and the App origin cannot reach it.
	if got := localRequest(server, http.MethodPost, "/v1/peer-key/pin-forget", `{"owner_account_id":"`+routeOwner+`","account_id":"`+routePeer+`"}`, session, csrf).Code; got != http.StatusNotFound {
		t.Fatalf("pin-forget = %d, want 404", got)
	}
	chain := make([]map[string]any, 40)
	for i := range chain {
		chain[i] = map[string]any{"account_id": routePeer, "old_public_key": peer.PublicKey, "new_public_key": peer.PublicKey, "reason": "routine"}
	}
	code, _, body = callRoute(t, server, session, csrf, "/v1/peer-key/chain-evaluate", map[string]any{
		"owner_account_id": routeOwner, "account_id": routePeer, "public_key": peer.PublicKey, "rotation_statements": chain,
	})
	if code != http.StatusOK {
		t.Fatalf("a long rotation chain did not reach the handler: %d %.200s", code, body)
	}
}

func TestArchiveUnwrapAndRewrapBindsTheRotationTarget(t *testing.T) {
	server, _ := newChatTestServer(t)
	store := server.app.Store.(*testdouble.MemorySecretStore)
	session, csrf := openTestSession(t, server)

	code, generated, body := callRoute(t, server, session, csrf, "/v1/archive/archive_key_generate", map[string]any{})
	if code != http.StatusOK || !generated.Success {
		t.Fatalf("generate: %d %s", code, body)
	}
	var archive proto.ArchiveKeyGenerateResponseData
	_ = json.Unmarshal(generated.Data, &archive)
	groupDEK := bytes.Repeat([]byte{0x55}, 32)
	wrapped := wrapTo(t, archive.PublicKey, groupDEK)
	rewrap := func(request map[string]any) (int, routeResult, string) {
		return callRoute(t, server, session, csrf, "/v1/archive/archive_unwrap_and_rewrap", request)
	}

	// No staged key yet: the rotation target does not exist.
	if code, _, _ := rewrap(map[string]any{"wrapped_for_archive_b64": wrapped, "to_staged_archive_key": true}); code != http.StatusBadRequest {
		t.Fatalf("rotation rewrap with nothing staged: %d", code)
	}
	if code, begun, body := callRoute(t, server, session, csrf, "/v1/archive/archive_key_rotate_begin", map[string]any{}); code != http.StatusOK || !begun.Success {
		t.Fatalf("rotate begin: %d %s", code, body)
	}
	code, result, body := rewrap(map[string]any{"wrapped_for_archive_b64": wrapped, "to_staged_archive_key": true})
	if code != http.StatusOK || !result.Success {
		t.Fatalf("rotation rewrap: %d %s", code, body)
	}
	var data proto.ArchiveUnwrapAndRewrapResponseData
	_ = json.Unmarshal(result.Data, &data)
	staged, _ := keychain.OrgArchiveStagingSlot("").GetPrivate(store)
	if !bytes.Equal(openWith(t, staged, data.EncryptedForOtherB64), groupDEK) {
		t.Fatal("the rotation rewrap is not to the staged archive key")
	}

	// Break-glass re-grants to a member's account key, judged by its pin.
	member, stranger := routeKeypair(t), routeKeypair(t)
	regrant := func(key string) map[string]any {
		return map[string]any{
			"wrapped_for_archive_b64": wrapped, "recipient_public_key": key,
			"owner_account_id": routeOwner, "recipient_account_id": routePeer,
		}
	}
	code, result, body = rewrap(regrant(member.PublicKey))
	if code != http.StatusOK || !result.Success {
		t.Fatalf("member re-grant: %d %s", code, body)
	}
	_ = json.Unmarshal(result.Data, &data)
	if !bytes.Equal(openWith(t, member.PrivateKey, data.EncryptedForOtherB64), groupDEK) {
		t.Fatal("the member re-grant did not reach the member")
	}
	code, result, body = rewrap(regrant(stranger.PublicKey))
	if code != http.StatusOK || result.Success || result.ErrorCode != "peer_key_changed" || strings.Contains(body, "encrypted_for_other") {
		t.Fatalf("re-grant to a changed key: %d %s", code, body)
	}

	// An ownership handoff goes to the new owner's account archive key, which
	// no pin tracks; the route says so by name.
	handoff := routeKeypair(t)
	code, result, body = rewrap(map[string]any{"wrapped_for_archive_b64": wrapped, "account_archive_public_key": handoff.PublicKey})
	if code != http.StatusOK || !result.Success {
		t.Fatalf("handoff rewrap: %d %s", code, body)
	}
	_ = json.Unmarshal(result.Data, &data)
	if !bytes.Equal(openWith(t, handoff.PrivateKey, data.EncryptedForOtherB64), groupDEK) {
		t.Fatal("the handoff rewrap did not reach the new owner")
	}

	for name, request := range map[string]map[string]any{
		"both targets":             {"wrapped_for_archive_b64": wrapped, "account_archive_public_key": member.PublicKey, "to_staged_archive_key": true},
		"no target":                {"wrapped_for_archive_b64": wrapped},
		"a false flag":             {"wrapped_for_archive_b64": wrapped, "to_staged_archive_key": false},
		"an extra field":           {"wrapped_for_archive_b64": wrapped, "account_archive_public_key": member.PublicKey, "target": "x"},
		"an unnamed recipient":     {"wrapped_for_archive_b64": wrapped, "recipient_public_key": member.PublicKey},
		"no owner":                 {"wrapped_for_archive_b64": wrapped, "recipient_public_key": member.PublicKey, "recipient_account_id": routePeer},
		"no recipient account":     {"wrapped_for_archive_b64": wrapped, "recipient_public_key": member.PublicKey, "owner_account_id": routeOwner},
		"a named handoff":          {"wrapped_for_archive_b64": wrapped, "account_archive_public_key": member.PublicKey, "recipient_account_id": routePeer, "owner_account_id": routeOwner},
		"a member and a handoff":   {"wrapped_for_archive_b64": wrapped, "recipient_public_key": member.PublicKey, "account_archive_public_key": member.PublicKey, "owner_account_id": routeOwner, "recipient_account_id": routePeer},
		"a staged key with a name": {"wrapped_for_archive_b64": wrapped, "to_staged_archive_key": true, "owner_account_id": routeOwner, "recipient_account_id": routePeer},
	} {
		if code, _, _ := rewrap(request); code != http.StatusBadRequest {
			t.Fatalf("rewrap with %s: %d", name, code)
		}
	}

	if code, committed, body := callRoute(t, server, session, csrf, "/v1/archive/archive_key_rotate_commit", map[string]any{}); code != http.StatusOK || !committed.Success {
		t.Fatalf("rotate commit: %d %s", code, body)
	}
	if code, _, _ := rewrap(map[string]any{"wrapped_for_archive_b64": wrapped, "to_staged_archive_key": true}); code != http.StatusBadRequest {
		t.Fatalf("rotation rewrap after commit: %d", code)
	}
}

func TestArchiveRoutesPassTheirTypedRequests(t *testing.T) {
	server, _ := newChatTestServer(t)
	session, csrf := openTestSession(t, server)
	for _, path := range []string{
		"/v1/archive/archive_key_status", "/v1/archive/account_archive_key_generate", "/v1/archive/account_archive_key_status",
		"/v1/archive/archive_key_generate", "/v1/archive/archive_key_rotate_abort", "/v1/archive/archive_session_begin",
		"/v1/archive/archive_session_end",
	} {
		if code, result, body := callRoute(t, server, session, csrf, path, map[string]any{}); code != http.StatusOK || !result.Success {
			t.Fatalf("%s: %d %s", path, code, body)
		}
		if code, _, _ := callRoute(t, server, session, csrf, path, map[string]any{"public_key": "x"}); code != http.StatusBadRequest {
			t.Fatalf("%s took an unknown field: %d", path, code)
		}
	}
	admins := []string{routeKeypair(t).PublicKey, routeKeypair(t).PublicKey, routeKeypair(t).PublicKey}
	code, result, body := callRoute(t, server, session, csrf, "/v1/archive/archive_key_split", map[string]any{
		"threshold_n": 2, "recipient_public_keys": admins,
	})
	if code != http.StatusOK || !result.Success {
		t.Fatalf("split: %d %s", code, body)
	}
	for _, path := range []string{"/v1/archive/archive_share_rewrap", "/v1/archive/archive_quorum_combine_and_rewrap", "/v1/archive/archive_key_split"} {
		if code, _, _ := callRoute(t, server, session, csrf, path, map[string]any{"session_private_key": "x"}); code != http.StatusBadRequest {
			t.Fatalf("%s took an unknown field: %d", path, code)
		}
	}
}

// The App rotation routes take org_id and keep each org's stage apart; the
// rotation rewrap targets the named org's stage.
func TestArchiveRotationRoutesAreOrgScoped(t *testing.T) {
	server, _ := newChatTestServer(t)
	store := server.app.Store.(*testdouble.MemorySecretStore)
	session, csrf := openTestSession(t, server)
	const orgA, orgB = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"

	code, generated, body := callRoute(t, server, session, csrf, "/v1/archive/archive_key_generate", map[string]any{})
	if code != http.StatusOK || !generated.Success {
		t.Fatalf("generate: %d %s", code, body)
	}
	var archive proto.ArchiveKeyGenerateResponseData
	_ = json.Unmarshal(generated.Data, &archive)
	groupDEK := bytes.Repeat([]byte{0x66}, 32)
	wrapped := wrapTo(t, archive.PublicKey, groupDEK)

	stages := map[string]proto.ArchiveKeyRotateBeginResponseData{}
	for _, org := range []string{orgA, orgB} {
		code, begun, body := callRoute(t, server, session, csrf, "/v1/archive/archive_key_rotate_begin", map[string]any{"org_id": org})
		if code != http.StatusOK || !begun.Success {
			t.Fatalf("begin %s: %d %s", org, code, body)
		}
		var stage proto.ArchiveKeyRotateBeginResponseData
		_ = json.Unmarshal(begun.Data, &stage)
		stages[org] = stage
	}

	code, result, body := callRoute(t, server, session, csrf, "/v1/archive/archive_unwrap_and_rewrap", map[string]any{
		"org_id": orgA, "wrapped_for_archive_b64": wrapped, "to_staged_archive_key": true,
	})
	if code != http.StatusOK || !result.Success {
		t.Fatalf("rotation rewrap A: %d %s", code, body)
	}
	var data proto.ArchiveUnwrapAndRewrapResponseData
	_ = json.Unmarshal(result.Data, &data)
	stagedA, _ := keychain.OrgArchiveStagingSlot(orgA).GetPrivate(store)
	if !bytes.Equal(openWith(t, stagedA, data.EncryptedForOtherB64), groupDEK) {
		t.Fatal("the rotation rewrap is not to org A's stage")
	}

	code, committed, body := callRoute(t, server, session, csrf, "/v1/archive/archive_key_rotate_commit", map[string]any{
		"org_id": orgB, "expected_fingerprint": stages[orgB].Fingerprint,
	})
	if code != http.StatusOK || !committed.Success {
		t.Fatalf("commit B: %d %s", code, body)
	}
	code, status, body := callRoute(t, server, session, csrf, "/v1/archive/archive_key_status", map[string]any{"org_id": orgA})
	if code != http.StatusOK || !status.Success {
		t.Fatalf("status A: %d %s", code, body)
	}
	var statusA proto.ArchiveKeyStatusResponseData
	_ = json.Unmarshal(status.Data, &statusA)
	if statusA.StagingFingerprint != stages[orgA].Fingerprint || statusA.Fingerprint != archive.Fingerprint {
		t.Fatalf("org A after B's commit: %+v", statusA)
	}
	if code, aborted, body := callRoute(t, server, session, csrf, "/v1/archive/archive_key_rotate_abort", map[string]any{"org_id": orgA}); code != http.StatusOK || !aborted.Success {
		t.Fatalf("abort A: %d %s", code, body)
	}
	for _, path := range []string{"/v1/archive/archive_key_rotate_begin", "/v1/archive/archive_key_rotate_commit"} {
		if code, _, _ := callRoute(t, server, session, csrf, path, map[string]any{"org_id": orgA, "public_key": "x"}); code != http.StatusBadRequest {
			t.Fatalf("%s took an unknown field: %d", path, code)
		}
	}
}

// Two App sessions claim at once through the routes: exactly one wins.
func TestChatRuntimeRouteClaimsRace(t *testing.T) {
	server, _ := newChatTestServer(t)
	type opened struct{ session, csrf, holder string }
	var sessions []opened
	for i := 0; i < 6; i++ {
		session, csrf := openTestSession(t, server)
		sessions = append(sessions, opened{session, csrf, "cmFjZS1ob2xkZXItMDAwMD" + string(rune('A'+i))})
	}
	var granted atomic.Int32
	var start, done sync.WaitGroup
	start.Add(1)
	for _, s := range sessions {
		done.Add(1)
		go func(s opened) {
			defer done.Done()
			start.Wait()
			if claimLease(t, server, s.session, s.csrf, s.holder).Success {
				granted.Add(1)
			}
		}(s)
	}
	start.Done()
	done.Wait()
	if granted.Load() != 1 {
		t.Fatalf("%d sessions won the lease", granted.Load())
	}
}

// An App claim and proxied Extension gated frames race: never both succeed.
func TestChatRuntimeRouteClaimAndProxiedFramesRace(t *testing.T) {
	for round := 0; round < 20; round++ {
		server, _ := newChatTestServer(t)
		session, csrf := openTestSession(t, server)
		var claimed atomic.Bool
		var extensionRan atomic.Int32
		var start, done sync.WaitGroup
		start.Add(1)
		done.Add(1)
		go func() {
			defer done.Done()
			start.Wait()
			claimed.Store(claimLease(t, server, session, csrf, routeHolder).Success)
		}()
		for range 3 {
			done.Add(1)
			go func() {
				defer done.Done()
				start.Wait()
				if proxiedFrame(t, server, leafAbortFrame).Success {
					extensionRan.Add(1)
				}
			}()
		}
		start.Done()
		done.Wait()
		if claimed.Load() == (extensionRan.Load() > 0) {
			t.Fatalf("round %d: claimed=%v extension ran %d", round, claimed.Load(), extensionRan.Load())
		}
	}
}
