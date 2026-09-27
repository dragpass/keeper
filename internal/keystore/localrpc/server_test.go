package localrpc

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dragpass/keeper/internal/keystore"
	keepercrypto "github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/localsecret"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

const testOrigin = "https://app.dragpass.io"

func testSecret(t *testing.T) localsecret.Secret {
	t.Helper()
	t.Setenv(localsecret.DirEnvVar, t.TempDir())
	secret, err := localsecret.LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	return secret
}

func newTestServer(t *testing.T) *Server {
	t.Helper()
	return newTestServerWithSecret(t, testSecret(t))
}

func newTestServerWithSecret(t *testing.T, secret localsecret.Secret) *Server {
	t.Helper()
	server, err := New(keystore.NewApp(keystore.Deps{Store: keystore.NewMemorySecretStore()}), []string{testOrigin, NativeExtensionOrigin}, secret)
	if err != nil {
		t.Fatal(err)
	}
	server.host = "127.0.0.1:47623"
	server.now = func() time.Time { return time.Unix(1_800_000_000, 0) }
	return server
}

func localRequest(server *Server, method, path, body, session, csrf string) *httptest.ResponseRecorder {
	return localRequestFromOrigin(server, method, path, body, session, csrf, testOrigin)
}

func localRequestFromOrigin(server *Server, method, path, body, session, csrf, origin string) *httptest.ResponseRecorder {
	return sessionRequest(server, method, path, body, session, csrf, origin, true)
}

// localRawRequest sends body as is, even inside a session.
func localRawRequest(server *Server, method, path, body, session, csrf string) *httptest.ResponseRecorder {
	return sessionRequest(server, method, path, body, session, csrf, testOrigin, false)
}

// sessionRequest seals a session request's body the way the App does and, on
// a 200, replaces the sealed answer with the plaintext it carries.
func sessionRequest(server *Server, method, path, body, session, csrf, origin string, seal bool) *httptest.ResponseRecorder {
	server.mu.Lock()
	current, open := server.sessions[session]
	server.mu.Unlock()
	requestNonce := ""
	if seal && open && method == http.MethodPost {
		envelope, err := sealEnvelope(current.key, appRequestAAD(current.origin, session, path), []byte(body))
		if err != nil {
			panic(err)
		}
		raw, _ := json.Marshal(envelope)
		body, requestNonce = string(raw), envelope.Nonce
	}
	request := httptest.NewRequest(method, "http://"+server.host+path, bytes.NewBufferString(body))
	request.Host = server.host
	request.RemoteAddr = "127.0.0.1:54321"
	request.Header.Set("Origin", origin)
	request.Header.Set("Sec-Fetch-Site", "cross-site")
	request.Header.Set("X-DragPass-Local-RPC", "1")
	if session != "" {
		request.Header.Set("Authorization", "Bearer "+session)
	}
	if csrf != "" {
		request.Header.Set("X-DragPass-CSRF", csrf)
	}
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if requestNonce != "" && recorder.Code == http.StatusOK {
		var envelope sealedEnvelope
		if err := json.Unmarshal(recorder.Body.Bytes(), &envelope); err != nil {
			panic(fmt.Sprintf("session answer is not sealed: %s", recorder.Body.String()))
		}
		plain, err := openEnvelope(current.key, envelope, appResponseAAD(current.origin, session, path, requestNonce))
		if err != nil {
			panic(fmt.Sprintf("session answer does not open: %v", err))
		}
		recorder.Body = bytes.NewBuffer(plain)
	}
	return recorder
}

func requestAppChallenge(t *testing.T, server *Server) string {
	t.Helper()
	response := localRequest(server, http.MethodPost, "/v1/session/challenge", "{}", "", "")
	if response.Code != http.StatusOK {
		t.Fatalf("session challenge: status=%d body=%s", response.Code, response.Body.String())
	}
	var result struct {
		Challenge string `json:"challenge"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil || result.Challenge == "" {
		t.Fatalf("session challenge body=%s err=%v", response.Body.String(), err)
	}
	return result.Challenge
}

func appOpenBody(key []byte, origin, challenge, clientNonce string) string {
	body, _ := json.Marshal(map[string]string{
		"challenge":    challenge,
		"client_nonce": clientNonce,
		"proof":        macB64(key, appOpenLabel, origin, challenge, clientNonce),
	})
	return string(body)
}

const testClientNonce = "Y2xpZW50LW5vbmNlLTE2Ynl0ZXM"

func openTestSession(t *testing.T, server *Server) (string, string) {
	t.Helper()
	challenge := requestAppChallenge(t, server)
	response := localRequest(server, http.MethodPost, "/v1/session", appOpenBody(server.appKey, testOrigin, challenge, testClientNonce), "", "")
	if response.Code != http.StatusOK {
		t.Fatalf("open session: status=%d body=%s", response.Code, response.Body.String())
	}
	var result struct {
		Session    string `json:"session"`
		CSRF       string `json:"csrf"`
		ExpiresAt  int64  `json:"expires_at"`
		OwnerProof string `json:"owner_proof"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	expected := mac(server.appKey, appOwnerLabel, testOrigin, challenge, testClientNonce, result.Session, result.CSRF, fmt.Sprint(result.ExpiresAt))
	if !equalMAC(expected, result.OwnerProof) {
		t.Fatalf("owner proof does not verify: %+v", result)
	}
	return result.Session, result.CSRF
}

func TestLocalRPCRequiresExactOriginHostAndLoopback(t *testing.T) {
	server := newTestServer(t)
	for name, mutate := range map[string]func(*http.Request){
		"untrusted origin": func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") },
		"host mismatch":    func(r *http.Request) { r.Host = "evil.example" },
		"remote address":   func(r *http.Request) { r.RemoteAddr = "203.0.113.2:443" },
		"missing origin":   func(r *http.Request) { r.Header.Del("Origin") },
	} {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "http://"+server.host+"/v1/session/challenge", bytes.NewBufferString("{}"))
			request.Host = server.host
			request.RemoteAddr = "127.0.0.1:54321"
			request.Header.Set("Origin", testOrigin)
			request.Header.Set("Sec-Fetch-Site", "cross-site")
			request.Header.Set("X-DragPass-Local-RPC", "1")
			mutate(request)
			recorder := httptest.NewRecorder()
			server.Handler().ServeHTTP(recorder, request)
			if recorder.Code != http.StatusForbidden {
				t.Fatalf("status=%d, want 403", recorder.Code)
			}
		})
	}
}

func TestLocalRPCPreflightGrantsOnlyConfiguredOrigin(t *testing.T) {
	server := newTestServer(t)
	request := httptest.NewRequest(http.MethodOptions, "http://"+server.host+"/v1/request-signature", nil)
	request.Host = server.host
	request.RemoteAddr = "127.0.0.1:54321"
	request.Header.Set("Origin", testOrigin)
	request.Header.Set("Sec-Fetch-Site", "cross-site")
	request.Header.Set("Access-Control-Request-Method", "POST")
	request.Header.Set("Access-Control-Request-Private-Network", "true")
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNoContent || recorder.Header().Get("Access-Control-Allow-Origin") != testOrigin || recorder.Header().Get("Access-Control-Allow-Private-Network") != "true" {
		t.Fatalf("preflight status=%d headers=%v", recorder.Code, recorder.Header())
	}
}

func TestLocalRPCSessionCSRFExpiryAndRevocation(t *testing.T) {
	server := newTestServer(t)
	session, csrf := openTestSession(t, server)
	if got := localRequest(server, http.MethodPost, "/v1/status", "{}", session, csrf).Code; got != http.StatusOK {
		t.Fatalf("status request=%d, want 200", got)
	}
	if got := localRequest(server, http.MethodPost, "/v1/request-signature", `{}`, session, "wrong").Code; got != http.StatusForbidden {
		t.Fatalf("invalid CSRF=%d, want 403", got)
	}
	if got := localRequest(server, http.MethodPost, "/v1/request-signature", `{}`, session, csrf).Code; got != http.StatusBadRequest {
		t.Fatalf("invalid signature request=%d, want 400", got)
	}
	if got := localRequest(server, http.MethodDelete, "/v1/session", "", session, "").Code; got != http.StatusNoContent {
		t.Fatalf("revoke=%d, want 204", got)
	}
	if got := localRequest(server, http.MethodPost, "/v1/status", "{}", session, csrf).Code; got != http.StatusUnauthorized {
		t.Fatalf("revoked session=%d, want 401", got)
	}

	session, _ = openTestSession(t, server)
	server.now = func() time.Time { return time.Unix(1_800_000_601, 0) }
	if got := localRequest(server, http.MethodPost, "/v1/status", "{}", session, csrf).Code; got != http.StatusUnauthorized {
		t.Fatalf("expired session=%d, want 401", got)
	}
}

func TestLocalRPCHealthReturnsOnlyBuildMetadata(t *testing.T) {
	server := newTestServer(t)
	response := localRequest(server, http.MethodGet, "/v1/health", "", "", "")
	if response.Code != http.StatusOK {
		t.Fatalf("health status=%d body=%s", response.Code, response.Body.String())
	}
	var result map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	_, hasHash := result["hash"].(string)
	if len(result) != 2 || result["version"] != "0.0.55" || !hasHash {
		t.Fatalf("unexpected health response: %#v", result)
	}
}

func proxyHealth(t *testing.T, server *Server, challenge string) *httptest.ResponseRecorder {
	t.Helper()
	path := "/v1/native-proxy/health"
	if challenge != "" {
		path += "?challenge=" + challenge
	}
	return localRequestFromOrigin(server, http.MethodGet, path, "", "", "", NativeExtensionOrigin)
}

func sealedPing(t *testing.T, key []byte, instance string, now time.Time) (string, string) {
	t.Helper()
	body, nonce, err := sealProxyRequest(key, instance, now, []byte(`{"action":"ping"}`))
	if err != nil {
		t.Fatal(err)
	}
	return string(body), nonce
}

func TestNativeMessagingProxyHealthProvesOwnerInstance(t *testing.T) {
	server := newTestServer(t)
	if got := proxyHealth(t, server, "").Code; got != http.StatusBadRequest {
		t.Fatalf("health without challenge=%d, want 400", got)
	}
	const challenge = "cHJveHktY2hhbGxlbmdlLTE2Yg"
	health := proxyHealth(t, server, challenge)
	if health.Code != http.StatusOK {
		t.Fatalf("proxy health status=%d body=%s", health.Code, health.Body.String())
	}
	var metadata struct {
		ProtocolVersion int    `json:"protocol_version"`
		Instance        string `json:"instance"`
		Proof           string `json:"proof"`
	}
	if err := json.Unmarshal(health.Body.Bytes(), &metadata); err != nil || metadata.ProtocolVersion != nativeProxyProtocolVersion {
		t.Fatalf("proxy health protocol=%d error=%v", metadata.ProtocolVersion, err)
	}
	if !equalMAC(healthProof(server.proxy.key, challenge, metadata.Instance), metadata.Proof) {
		t.Fatal("owner health proof does not verify")
	}
	if equalMAC(healthProof(testSecret(t).NativeProxyKey(), challenge, metadata.Instance), metadata.Proof) {
		t.Fatal("health proof verifies under an unrelated secret")
	}

	appOrigin := localRequestFromOrigin(server, http.MethodGet, "/v1/native-proxy/health?challenge="+challenge, "", "", "", testOrigin)
	if appOrigin.Code != http.StatusNotFound {
		t.Fatalf("App origin accessed extension proxy route: status=%d", appOrigin.Code)
	}
}

// Before this fix any local process that set the extension Origin could run
// every Keeper action here in plain JSON.
func TestNativeMessagingProxyRefusesUnsealedAndForeignRequests(t *testing.T) {
	server := newTestServer(t)
	if got := localRequestFromOrigin(server, http.MethodPost, "/v1/native-proxy/message", `{"action":"ping"}`, "", "", NativeExtensionOrigin).Code; got != http.StatusForbidden {
		t.Fatalf("plain JSON action=%d, want 403", got)
	}
	foreign, _ := sealedPing(t, testSecret(t).NativeProxyKey(), server.proxy.instance, server.now())
	if got := localRequestFromOrigin(server, http.MethodPost, "/v1/native-proxy/message", foreign, "", "", NativeExtensionOrigin).Code; got != http.StatusForbidden {
		t.Fatalf("request sealed with another user's key=%d, want 403", got)
	}
	stale, _ := sealedPing(t, server.proxy.key, server.proxy.instance, server.now().Add(-2*time.Minute))
	if got := localRequestFromOrigin(server, http.MethodPost, "/v1/native-proxy/message", stale, "", "", NativeExtensionOrigin).Code; got != http.StatusForbidden {
		t.Fatalf("stale request=%d, want 403", got)
	}
	otherInstance, _ := sealedPing(t, server.proxy.key, "previous-owner", server.now())
	if got := localRequestFromOrigin(server, http.MethodPost, "/v1/native-proxy/message", otherInstance, "", "", NativeExtensionOrigin).Code; got != http.StatusConflict {
		t.Fatalf("request for another owner instance=%d, want 409", got)
	}
}

func TestNativeMessagingProxySealedRoundTripRejectsReplay(t *testing.T) {
	server := newTestServer(t)
	body, nonce := sealedPing(t, server.proxy.key, server.proxy.instance, server.now())
	response := localRequestFromOrigin(server, http.MethodPost, "/v1/native-proxy/message", body, "", "", NativeExtensionOrigin)
	if response.Code != http.StatusOK {
		t.Fatalf("sealed ping status=%d body=%s", response.Code, response.Body.String())
	}
	plain, err := openProxyResponse(server.proxy.key, server.proxy.instance, nonce, response.Body.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	var result proto.BaseResponse
	if err := json.Unmarshal(plain, &result); err != nil || !result.Success {
		t.Fatalf("shared Keeper rejected ping: %s err=%v", plain, err)
	}
	if strings.Contains(response.Body.String(), "success") {
		t.Fatalf("response travelled unsealed: %s", response.Body.String())
	}
	if got := localRequestFromOrigin(server, http.MethodPost, "/v1/native-proxy/message", body, "", "", NativeExtensionOrigin).Code; got != http.StatusForbidden {
		t.Fatalf("replayed request=%d, want 403", got)
	}
}

func TestNativeMessagingProxyRejectsOversizedBody(t *testing.T) {
	server := newTestServer(t)
	body := strings.Repeat("x", int(maxNativeMessageBytes)*2)
	response := localRequestFromOrigin(server, http.MethodPost, "/v1/native-proxy/message", body, "", "", NativeExtensionOrigin)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("oversized proxy body status=%d, want 400", response.Code)
	}
}

func startTestOwner(t *testing.T, server *Server) string {
	t.Helper()
	server.now = time.Now
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server.host = listener.Addr().String()
	httpServer := &httptest.Server{Config: &http.Server{Handler: server.Handler()}, Listener: listener}
	httpServer.Start()
	t.Cleanup(httpServer.Close)
	return server.host
}

func TestNativeMessagingProxyProbesAndForwardsToExistingOwner(t *testing.T) {
	secret := testSecret(t)
	address := startTestOwner(t, newTestServerWithSecret(t, secret))

	role, listener, proxy, err := acquireNativeOwnerAt(address, secret.NativeProxyKey(), time.Second)
	if err != nil || role != RoleProxy || listener != nil || proxy == nil {
		if listener != nil {
			_ = listener.Close()
		}
		t.Fatalf("acquire existing owner: role=%v listener=%v error=%v", role, listener, err)
	}
	response, err := proxy.Forward([]byte(`{"action":"ping"}`))
	if err != nil || !response.Success {
		t.Fatalf("forwarded ping: response=%+v error=%v", response, err)
	}
}

func TestNativeMessagingProxyReprovesAfterOwnerRestart(t *testing.T) {
	secret := testSecret(t)
	first := newTestServerWithSecret(t, secret)
	address := startTestOwner(t, first)
	_, _, proxy, err := acquireNativeOwnerAt(address, secret.NativeProxyKey(), time.Second)
	if err != nil || proxy == nil {
		t.Fatalf("acquire: %v", err)
	}
	first.proxy.instance = "restarted-owner"
	if response, err := proxy.Forward([]byte(`{"action":"ping"}`)); err != nil || !response.Success {
		t.Fatalf("forward after owner restart: response=%+v error=%v", response, err)
	}
}

// A listener that cannot prove the local secret is another user's Keeper or a
// port squatter. The Native Messaging host must not send it anything and runs
// on its own stdio instead, as it did before the shared owner existed.
func TestNativeMessagingHostRunsStandaloneForUnprovenOwner(t *testing.T) {
	foreign := startTestOwner(t, newTestServerWithSecret(t, testSecret(t)))
	role, listener, proxy, err := acquireNativeOwnerAt(foreign, testSecret(t).NativeProxyKey(), time.Second)
	if err != nil || role != RoleStandalone || listener != nil || proxy != nil {
		t.Fatalf("foreign owner: role=%v listener=%v proxy=%v error=%v", role, listener, proxy, err)
	}

	incompatible, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	notFound := &httptest.Server{Config: &http.Server{Handler: http.NotFoundHandler()}, Listener: incompatible}
	notFound.Start()
	defer notFound.Close()
	role, listener, proxy, err = acquireNativeOwnerAt(incompatible.Addr().String(), testSecret(t).NativeProxyKey(), 150*time.Millisecond)
	if err != nil || role != RoleStandalone || listener != nil || proxy != nil {
		t.Fatalf("incompatible listener: role=%v listener=%v proxy=%v error=%v", role, listener, proxy, err)
	}
}

func TestNativeMessagingOwnerClaimsFreeAddressBeforeInitialization(t *testing.T) {
	reservation, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := reservation.Addr().String()
	if err := reservation.Close(); err != nil {
		t.Fatal(err)
	}
	role, listener, proxy, err := acquireNativeOwnerAt(address, testSecret(t).NativeProxyKey(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if role != RoleOwner || proxy != nil || listener.Addr().String() != address {
		t.Fatalf("free address ownership: role=%v listener=%v", role, listener)
	}
}

func TestNativeMessagingOwnerWaitsForListenerStartupThenForwards(t *testing.T) {
	secret := testSecret(t)
	server := newTestServerWithSecret(t, secret)
	server.now = time.Now
	httpServer := &httptest.Server{Config: &http.Server{Handler: server.Handler()}}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	httpServer.Listener = listener
	server.host = listener.Addr().String()
	address := listener.Addr().String()
	started := make(chan struct{})
	go func() {
		time.Sleep(150 * time.Millisecond)
		httpServer.Start()
		close(started)
	}()
	t.Cleanup(func() {
		<-started
		httpServer.Close()
	})

	role, owner, proxy, err := acquireNativeOwnerAt(address, secret.NativeProxyKey(), 2*time.Second)
	if err != nil || role != RoleProxy || owner != nil {
		if owner != nil {
			_ = owner.Close()
		}
		t.Fatalf("startup race result: role=%v listener=%v error=%v", role, owner, err)
	}
	response, err := proxy.Forward([]byte(`{"action":"ping"}`))
	if err != nil || !response.Success {
		t.Fatalf("forward after owner startup: response=%+v error=%v", response, err)
	}
}

func TestAppServiceWaitsForNativeMessagingOwnerToReleaseAddress(t *testing.T) {
	server := newTestServer(t)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server.host = listener.Addr().String()
	httpServer := &http.Server{Handler: server.Handler()}
	serveDone := make(chan struct{})
	go func() {
		_ = httpServer.Serve(listener)
		close(serveDone)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	go func() {
		time.Sleep(150 * time.Millisecond)
		_ = httpServer.Close()
	}()

	owner, err := acquireAppServiceOwnerAt(ctx, server.host, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	<-serveDone
	if owner.Addr().String() != server.host {
		t.Fatalf("App service claimed %s, want %s", owner.Addr(), server.host)
	}
}

func TestAppSessionRequiresPairingProof(t *testing.T) {
	server := newTestServer(t)
	if got := localRequest(server, http.MethodPost, "/v1/session", "{}", "", "").Code; got != http.StatusUnauthorized {
		t.Fatalf("session without proof=%d, want 401", got)
	}
	challenge := requestAppChallenge(t, server)
	otherKey := testSecret(t).AppPairingKey()
	if got := localRequest(server, http.MethodPost, "/v1/session", appOpenBody(otherKey, testOrigin, challenge, testClientNonce), "", "").Code; got != http.StatusUnauthorized {
		t.Fatalf("session proved with another user's key=%d, want 401", got)
	}
	// The failed attempt consumed the challenge: a proof over it cannot be
	// replayed, even a correct one.
	if got := localRequest(server, http.MethodPost, "/v1/session", appOpenBody(server.appKey, testOrigin, challenge, testClientNonce), "", "").Code; got != http.StatusUnauthorized {
		t.Fatalf("session reused a consumed challenge=%d, want 401", got)
	}
	unknown := "dW5rbm93bi1jaGFsbGVuZ2UtMTZi"
	if got := localRequest(server, http.MethodPost, "/v1/session", appOpenBody(server.appKey, testOrigin, unknown, testClientNonce), "", "").Code; got != http.StatusUnauthorized {
		t.Fatalf("session over a challenge this owner never issued=%d, want 401", got)
	}
	challenge = requestAppChallenge(t, server)
	server.now = func() time.Time { return time.Unix(1_800_000_031, 0) }
	if got := localRequest(server, http.MethodPost, "/v1/session", appOpenBody(server.appKey, testOrigin, challenge, testClientNonce), "", "").Code; got != http.StatusUnauthorized {
		t.Fatalf("session over an expired challenge=%d, want 401", got)
	}
	server.now = func() time.Time { return time.Unix(1_800_000_000, 0) }
	openTestSession(t, server)
}

func TestAppOriginsIncludeDevOriginOnlyOnOptIn(t *testing.T) {
	env := map[string]string{}
	getenv := func(key string) string { return env[key] }
	for _, origin := range AppOrigins(getenv) {
		if strings.HasPrefix(origin, "http://") {
			t.Fatalf("production origins include %s", origin)
		}
	}
	env[DevAppOriginEnvVar] = "http://localhost:5174"
	found := false
	for _, origin := range AppOrigins(getenv) {
		found = found || origin == "http://localhost:5174"
	}
	if !found {
		t.Fatal("dev origin missing after opt-in")
	}
}

func TestLocalRPCDoesNotExposeArbitraryKeeperActions(t *testing.T) {
	server := newTestServer(t)
	session, csrf := openTestSession(t, server)
	if got := localRequest(server, http.MethodPost, "/v1/action/group_dek_export", `{}`, session, csrf).Code; got != http.StatusNotFound {
		t.Fatalf("arbitrary action route=%d, want 404", got)
	}
}

func TestLocalRPCAppLoginSigningUsesTypedActions(t *testing.T) {
	server := newTestServer(t)
	pair, err := keepercrypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := keychain.SavePrivateKey(server.app.Store, pair.PrivateKey); err != nil {
		t.Fatal(err)
	}
	session, csrf := openTestSession(t, server)

	response := localRequest(server, http.MethodPost, "/v1/auth/login/sign-alias", `{"alias":"alice"}`, session, csrf)
	if response.Code != http.StatusOK {
		t.Fatalf("sign alias status=%d body=%s", response.Code, response.Body.String())
	}
	var result struct {
		Success bool `json:"success"`
		Data    struct {
			Signature string `json:"signature"`
			Timestamp int64  `json:"timestamp"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if !result.Success || result.Data.Signature == "" || abs(time.Now().Unix()-result.Data.Timestamp) > 60 {
		t.Fatalf("unexpected login signature response: %+v", result)
	}

	unknownField := localRequest(server, http.MethodPost, "/v1/auth/login/sign-alias", `{"alias":"alice","action":"group_dek_export"}`, session, csrf)
	if unknownField.Code != http.StatusBadRequest {
		t.Fatalf("unknown action field status=%d, want 400", unknownField.Code)
	}

	withoutCSRF := localRequest(server, http.MethodPost, "/v1/auth/login/sign-alias", `{"alias":"alice"}`, session, "wrong")
	if withoutCSRF.Code != http.StatusForbidden {
		t.Fatalf("invalid CSRF status=%d, want 403", withoutCSRF.Code)
	}
}

func TestLocalRPCAppSignupUsesTypedKeeperRoutes(t *testing.T) {
	server := newTestServer(t)
	session, csrf := openTestSession(t, server)
	body := `{"alias":"alice","password":"correct horse battery staple","recovery_key":"ABCD-EFGH-JKLM-NPQR-STUV-WXYZ"}`
	response := localRequest(server, http.MethodPost, "/v1/auth/signup/prepare", body, session, csrf)
	if response.Code != http.StatusOK {
		t.Fatalf("signup preparation status=%d body=%s", response.Code, response.Body.String())
	}
	var result proto.BaseResponse
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if !result.Success {
		t.Fatalf("signup preparation failed: %s", response.Body.String())
	}
	if bytes.Contains(response.Body.Bytes(), []byte("correct horse battery staple")) || bytes.Contains(response.Body.Bytes(), []byte("ABCD-EFGH-JKLM-NPQR-STUV-WXYZ")) {
		t.Fatalf("signup response echoed request secrets: %s", response.Body.String())
	}
	unknown := localRequest(server, http.MethodPost, "/v1/auth/signup/prepare", body[:len(body)-1]+`,"action":"group_dek_export"}`, session, csrf)
	if unknown.Code != http.StatusBadRequest {
		t.Fatalf("unknown field status=%d, want 400", unknown.Code)
	}
}

func TestLocalRPCRestoresDeviceMasterWithoutReturningWrappedMaterial(t *testing.T) {
	server := newTestServer(t)
	deviceKey := bytes.Repeat([]byte{0x5a}, 32)
	if err := keychain.SaveDeviceKey(server.app.Store, base64.StdEncoding.EncodeToString(deviceKey)); err != nil {
		t.Fatal(err)
	}
	setup, err := json.Marshal(map[string]any{
		"action":  proto.ActionDEKGenerateAndWrapDual,
		"payload": map[string]string{"password": "correct-password"},
	})
	if err != nil {
		t.Fatal(err)
	}
	signup := server.app.HandleRequest(setup)
	if !signup.Success {
		t.Fatalf("generate password-wrapped DEK: %+v", signup)
	}
	wrapped := signup.Data.(proto.DEKGenerateAndWrapDualResponseData).PasswordWrappedDEKB64
	session, csrf := openTestSession(t, server)
	body, err := json.Marshal(map[string]string{
		"password":          "correct-password",
		"encrypted_dek_b64": wrapped,
	})
	if err != nil {
		t.Fatal(err)
	}
	response := localRequest(server, http.MethodPost, "/v1/auth/login/restore-device-master", string(body), session, csrf)
	if response.Code != http.StatusOK {
		t.Fatalf("restore status=%d body=%s", response.Code, response.Body.String())
	}
	var result struct {
		Success bool `json:"success"`
		Data    struct {
			Stored bool `json:"stored"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if !result.Success || !result.Data.Stored || bytes.Contains(response.Body.Bytes(), []byte(wrapped)) {
		t.Fatalf("restore response exposed unexpected data: %s", response.Body.String())
	}
	stored, err := keychain.GetPersonalDeviceWrappedDEK(server.app.Store)
	if err != nil || stored == "" {
		t.Fatalf("device-wrapped DEK was not saved: value=%q error=%v", stored, err)
	}

	wrongPassword := strings.Replace(string(body), "correct-password", "wrong-password", 1)
	failed := localRequest(server, http.MethodPost, "/v1/auth/login/restore-device-master", wrongPassword, session, csrf)
	var failure struct {
		Success bool `json:"success"`
	}
	if err := json.Unmarshal(failed.Body.Bytes(), &failure); err != nil {
		t.Fatal(err)
	}
	if failed.Code != http.StatusOK || failure.Success {
		t.Fatalf("wrong password was accepted: status=%d body=%s", failed.Code, failed.Body.String())
	}
	storedAfterFailure, err := keychain.GetPersonalDeviceWrappedDEK(server.app.Store)
	if err != nil || storedAfterFailure != stored {
		t.Fatalf("failed restore changed stored DEK: before=%q after=%q error=%v", stored, storedAfterFailure, err)
	}

	unknownField := localRequest(server, http.MethodPost, "/v1/auth/login/restore-device-master", `{"password":"x","encrypted_dek_b64":"AA==","action":"group_dek_export"}`, session, csrf)
	if unknownField.Code != http.StatusBadRequest {
		t.Fatalf("unknown action field status=%d, want 400", unknownField.Code)
	}
	withoutCSRF := localRequest(server, http.MethodPost, "/v1/auth/login/restore-device-master", string(body), session, "wrong")
	if withoutCSRF.Code != http.StatusForbidden {
		t.Fatalf("missing CSRF status=%d, want 403", withoutCSRF.Code)
	}
}

func TestLocalRPCEnsuresRequestKeyThroughTypedLoginRoute(t *testing.T) {
	server := newTestServer(t)
	session, csrf := openTestSession(t, server)
	response := localRequest(server, http.MethodPost, "/v1/auth/login/ensure-request-key", `{}`, session, csrf)
	if response.Code != http.StatusOK {
		t.Fatalf("ensure request key status=%d body=%s", response.Code, response.Body.String())
	}
	var result struct {
		Success bool `json:"success"`
		Data    struct {
			PublicKey   string `json:"publickey"`
			Fingerprint string `json:"fingerprint"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if !result.Success || result.Data.PublicKey == "" || result.Data.Fingerprint == "" {
		t.Fatalf("request key metadata missing: %s", response.Body.String())
	}
	if strings.Contains(response.Body.String(), "private") || strings.Contains(response.Body.String(), "secret") {
		t.Fatalf("request key response includes unexpected private field: %s", response.Body.String())
	}
	unknownField := localRequest(server, http.MethodPost, "/v1/auth/login/ensure-request-key", `{"action":"group_dek_export"}`, session, csrf)
	if unknownField.Code != http.StatusBadRequest {
		t.Fatalf("unknown request key action field status=%d, want 400", unknownField.Code)
	}
}

func abs(value int64) int64 {
	if value < 0 {
		return -value
	}
	return value
}

func TestLocalRPCSignsStructuredRequestOnce(t *testing.T) {
	server := newTestServer(t)
	generated, err := json.Marshal(map[string]string{"action": "request_key_generate"})
	if err != nil {
		t.Fatal(err)
	}
	if response := server.app.HandleRequest(generated); !response.Success {
		t.Fatalf("request key generation failed: %+v", response)
	}
	session, csrf := openTestSession(t, server)
	body := fmt.Sprintf(`{"method":"POST","path":"/api/v1/chat/messages","query":"","timestamp":"%d","nonce":"AAAAAAAAAAAAAAAAAAAAAA","body_sha256":"%064d","account_id":"11111111-1111-4111-8111-111111111111","token_id":"22222222-2222-4222-8222-222222222222","device_id":"device-12345678"}`, server.now().Unix(), 0)
	first := localRequest(server, http.MethodPost, "/v1/request-signature", body, session, csrf)
	if first.Code != http.StatusOK {
		t.Fatalf("sign request: status=%d body=%s", first.Code, first.Body.String())
	}
	var response struct {
		Success bool `json:"success"`
	}
	if err := json.Unmarshal(first.Body.Bytes(), &response); err != nil || !response.Success {
		t.Fatalf("invalid keeper response: body=%s error=%v", first.Body.String(), err)
	}
	second := localRequest(server, http.MethodPost, "/v1/request-signature", body, session, csrf)
	if second.Code != http.StatusConflict {
		t.Fatalf("replayed request status=%d, want 409", second.Code)
	}
}

func TestLocalRPCRejectsOversizedAndNonCanonicalInputs(t *testing.T) {
	server := newTestServer(t)
	session, csrf := openTestSession(t, server)
	oversized := strings.Repeat("x", maxRequestBytes+1)
	if got := localRequest(server, http.MethodPost, "/v1/request-signature", oversized, session, csrf).Code; got != http.StatusBadRequest {
		t.Fatalf("oversized request=%d, want 400", got)
	}
	base := requestSignature{
		Method: "GET", Path: "/api/v1/account/me", Query: "a=1&b=2",
		Timestamp: "1800000000", Nonce: "AAAAAAAAAAAAAAAAAAAAAA",
		BodySHA256: strings.Repeat("0", 64),
		AccountID:  "11111111-1111-4111-8111-111111111111",
		TokenID:    "22222222-2222-4222-8222-222222222222", DeviceID: "device-12345678",
	}
	if err := validateRequestSignature(base, server.now()); err != nil {
		t.Fatalf("valid signing request was rejected: %v", err)
	}
	base.Timestamp = "1799999939"
	if err := validateRequestSignature(base, server.now()); err == nil {
		t.Fatal("stale timestamp was accepted")
	}
	base.Timestamp = "1800000000"
	base.Query = "b=2&a=1"
	if err := validateRequestSignature(base, server.now()); err == nil {
		t.Fatal("non-canonical query was accepted")
	}
	base.Query = "a=1&b=2"
	base.Path = "/api/v1/../admin/users"
	if err := validateRequestSignature(base, server.now()); err == nil {
		t.Fatal("path traversal was accepted")
	}
}

func TestLocalRPCConcurrentReplayHasOneSigner(t *testing.T) {
	server := newTestServer(t)
	generated, err := json.Marshal(map[string]string{"action": "request_key_generate"})
	if err != nil {
		t.Fatal(err)
	}
	if response := server.app.HandleRequest(generated); !response.Success {
		t.Fatalf("request key generation failed: %+v", response)
	}
	session, csrf := openTestSession(t, server)
	body := fmt.Sprintf(`{"method":"POST","path":"/api/v1/chat/messages","query":"","timestamp":"%d","nonce":"AAAAAAAAAAAAAAAAAAAAAA","body_sha256":"%064d","account_id":"11111111-1111-4111-8111-111111111111","token_id":"22222222-2222-4222-8222-222222222222","device_id":"device-12345678"}`, server.now().Unix(), 0)
	var wait sync.WaitGroup
	statuses := make(chan int, 2)
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			statuses <- localRequest(server, http.MethodPost, "/v1/request-signature", body, session, csrf).Code
		}()
	}
	wait.Wait()
	close(statuses)
	counts := map[int]int{}
	for status := range statuses {
		counts[status]++
	}
	if counts[http.StatusOK] != 1 || counts[http.StatusConflict] != 1 {
		t.Fatalf("concurrent replay statuses=%v, want one 200 and one 409", counts)
	}
}

// The App computes these proofs in TypeScript (dragpass
// app/src/shared/keeper/local-keeper-client.test.ts pins the same vectors).
func TestAppSessionProofVectorsMatchTheApp(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	if got := macB64(key, appOpenLabel, "https://app.dragpass.io", "owner-challenge", "client-nonce"); got != "qg6VblYr2SCWztw8ULsJZTQIymzOQSbWqlvtR5gCUfc" {
		t.Fatalf("open proof vector = %s", got)
	}
	if got := macB64(key, appOwnerLabel, "https://app.dragpass.io", "owner-challenge", "client-nonce", "local-session", "csrf-token", "1900000000"); got != "RipQFJrpaNfrivmVrPFcyykiAHzxQE83rEC_hi0kdbM" {
		t.Fatalf("owner proof vector = %s", got)
	}
}

func TestAppSessionRequestsMustBeSealedToTheSession(t *testing.T) {
	server := newTestServer(t)
	session, csrf := openTestSession(t, server)
	if got := localRawRequest(server, http.MethodPost, "/v1/auth/login/sign-alias", `{"alias":"alice"}`, session, csrf).Code; got != http.StatusForbidden {
		t.Fatalf("plaintext request in a session=%d, want 403", got)
	}

	server.mu.Lock()
	current := server.sessions[session]
	server.mu.Unlock()
	sealFor := func(key []byte, path string) string {
		envelope, err := sealEnvelope(key, appRequestAAD(testOrigin, session, path), []byte(`{"alias":"alice"}`))
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(envelope)
		return string(raw)
	}
	if got := localRawRequest(server, http.MethodPost, "/v1/auth/login/sign-alias", sealFor(testSecret(t).AppPairingKey(), "/v1/auth/login/sign-alias"), session, csrf).Code; got != http.StatusForbidden {
		t.Fatalf("request sealed under another key=%d, want 403", got)
	}
	moved := sealFor(current.key, "/v1/auth/signup/prepare")
	if got := localRawRequest(server, http.MethodPost, "/v1/auth/login/sign-alias", moved, session, csrf).Code; got != http.StatusForbidden {
		t.Fatalf("request sealed for another route=%d, want 403", got)
	}
	once := sealFor(current.key, "/v1/auth/login/sign-alias")
	first := localRawRequest(server, http.MethodPost, "/v1/auth/login/sign-alias", once, session, csrf)
	if first.Code != http.StatusOK {
		t.Fatalf("sealed request=%d body=%s", first.Code, first.Body.String())
	}
	if strings.Contains(first.Body.String(), "success") {
		t.Fatalf("the answer travelled in the clear: %s", first.Body.String())
	}
	if got := localRawRequest(server, http.MethodPost, "/v1/auth/login/sign-alias", once, session, csrf).Code; got != http.StatusConflict {
		t.Fatalf("replayed envelope=%d, want 409", got)
	}
	if got := localRequestFromOrigin(server, http.MethodPost, "/v1/status", "{}", session, csrf, NativeExtensionOrigin).Code; got != http.StatusForbidden {
		t.Fatalf("session used from another origin=%d, want 403", got)
	}
}

// The App derives the session key and seals in TypeScript (dragpass
// app/src/shared/keeper/local-keeper-client.test.ts pins the same vectors).
func TestAppSessionSealVectorsMatchTheApp(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	sessionKey := appSessionKey(key, "https://app.dragpass.io", "owner-challenge", "client-nonce", "local-session", "csrf-token", 1900000000)
	if got := base64.RawURLEncoding.EncodeToString(sessionKey); got != "AW5ZsIFkocjYd7b_hBCKil-yovRAMhV_Q7FEZfZc0R4" {
		t.Fatalf("session key vector = %s", got)
	}
	aead, err := newAEAD(sessionKey)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, aead.NonceSize())
	sealed := aead.Seal(nil, nonce, []byte(`{"alias":"alice"}`), appRequestAAD("https://app.dragpass.io", "local-session", "/v1/auth/login/sign-alias"))
	if got := base64.RawURLEncoding.EncodeToString(sealed); got != "Egv5bAq_p6mEkX08FjZPUgDcWfZXU3gJ-wt6GDHisSrI" {
		t.Fatalf("request seal vector = %s", got)
	}
	answer := aead.Seal(nil, nonce, []byte(`{"success":true}`), appResponseAAD("https://app.dragpass.io", "local-session", "/v1/auth/login/sign-alias", "AAAAAAAAAAAAAAAA"))
	if got := base64.RawURLEncoding.EncodeToString(answer); got != "EgvrdQC9sfjNkSYkDSBPDagAz5FH6baw344aGVN01DY" {
		t.Fatalf("response seal vector = %s", got)
	}
}
