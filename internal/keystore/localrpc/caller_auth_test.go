package localrpc

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// These tests call the local RPC handler directly, the way a page in another
// origin, another extension or a local process that is not the App would,
// and check that nothing it sends gets a Keeper action run or an answer read.
// The browser-context checks (Origin, Host, Sec-Fetch-Site, the custom
// header) only stop browsers; the pairing key and the session seal are the
// authentication, and both are exercised here without the App client.

// rawRequest builds a request with every browser header the App sends, for a
// test to alter one at a time.
func rawRequest(server *Server, method, path, body string) *http.Request {
	request := httptest.NewRequest(method, "http://"+server.host+path, bytes.NewBufferString(body))
	request.Host = server.host
	request.RemoteAddr = "127.0.0.1:54321"
	request.Header.Set("Origin", testOrigin)
	request.Header.Set("Sec-Fetch-Site", "cross-site")
	request.Header.Set("X-DragPass-Local-RPC", "1")
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	return request
}

func serve(server *Server, request *http.Request) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	return recorder
}

// assertNoCORSGrant fails when a refused answer still tells a browser it may
// read it.
func assertNoCORSGrant(t *testing.T, recorder *httptest.ResponseRecorder) {
	t.Helper()
	if got := recorder.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("refused answer grants origin %q", got)
	}
	if got := recorder.Header().Get("Access-Control-Allow-Credentials"); got != "" {
		t.Fatalf("refused answer allows credentials: %q", got)
	}
}

func TestForgedBrowserContextIsRefusedOnEveryRoute(t *testing.T) {
	server := newTestServer(t)
	routes := []struct{ method, path, body string }{
		{http.MethodGet, "/v1/health", ""},
		{http.MethodPost, "/v1/session/challenge", "{}"},
		{http.MethodPost, "/v1/session", "{}"},
		{http.MethodDelete, "/v1/session", ""},
		{http.MethodPost, "/v1/status", "{}"},
		{http.MethodPost, "/v1/request-signature", "{}"},
		{http.MethodPost, "/v1/message/display", "{}"},
		{http.MethodPost, "/v1/chat/mls_room_name_open", "{}"},
		{http.MethodGet, "/v1/native-proxy/health?challenge=cHJveHktY2hhbGxlbmdlLTE2Yg", ""},
		{http.MethodPost, "/v1/native-proxy/message", "{}"},
	}
	forgeries := map[string]func(*http.Request){
		"another site":                 func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") },
		"null origin":                  func(r *http.Request) { r.Header.Set("Origin", "null") },
		"look-alike suffix":            func(r *http.Request) { r.Header.Set("Origin", "https://app.dragpass.io.evil.example") },
		"look-alike prefix":            func(r *http.Request) { r.Header.Set("Origin", "https://evilapp.dragpass.io") },
		"plain http app origin":        func(r *http.Request) { r.Header.Set("Origin", "http://app.dragpass.io") },
		"origin with a path":           func(r *http.Request) { r.Header.Set("Origin", "https://app.dragpass.io/") },
		"origin in another case":       func(r *http.Request) { r.Header.Set("Origin", "https://APP.dragpass.io") },
		"origin with a port":           func(r *http.Request) { r.Header.Set("Origin", "https://app.dragpass.io:443") },
		"another extension":            func(r *http.Request) { r.Header.Set("Origin", "chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") },
		"extension origin with a path": func(r *http.Request) { r.Header.Set("Origin", NativeExtensionOrigin+"/") },
		"two origins":                  func(r *http.Request) { r.Header["Origin"] = []string{"https://evil.example", testOrigin} },
		"no origin, only a referer": func(r *http.Request) {
			r.Header.Del("Origin")
			r.Header.Set("Referer", testOrigin+"/")
		},
		"rebinding host":        func(r *http.Request) { r.Host = "evil.example:47623" },
		"localhost host":        func(r *http.Request) { r.Host = "localhost:47623" },
		"host without the port": func(r *http.Request) { r.Host = "127.0.0.1" },
		"host on another port":  func(r *http.Request) { r.Host = "127.0.0.1:47624" },
		"ipv6 loopback host":    func(r *http.Request) { r.Host = "[::1]:47623" },
		"app host":              func(r *http.Request) { r.Host = "app.dragpass.io" },
		"same-origin fetch":     func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "same-origin") },
		"navigation":            func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "none") },
		"no fetch metadata":     func(r *http.Request) { r.Header.Del("Sec-Fetch-Site") },
		"no custom header":      func(r *http.Request) { r.Header.Del("X-DragPass-Local-RPC") },
		"custom header true":    func(r *http.Request) { r.Header.Set("X-DragPass-Local-RPC", "true") },
		"remote peer":           func(r *http.Request) { r.RemoteAddr = "192.168.1.20:40000" },
	}
	for name, forge := range forgeries {
		for _, route := range routes {
			t.Run(name+" "+route.method+" "+route.path, func(t *testing.T) {
				request := rawRequest(server, route.method, route.path, route.body)
				forge(request)
				recorder := serve(server, request)
				if recorder.Code != http.StatusForbidden {
					t.Fatalf("status=%d body=%s, want 403", recorder.Code, recorder.Body.String())
				}
				// The refusal may name the request's own origin only when that
				// origin is an allowed one (the forgery was elsewhere).
				granted := recorder.Header().Get("Access-Control-Allow-Origin")
				if _, allowed := server.origins[granted]; granted != "" && (!allowed || granted != request.Header.Get("Origin")) {
					t.Fatalf("refused answer grants origin %q", granted)
				}
				if got := recorder.Header().Get("Access-Control-Allow-Credentials"); got != "" {
					t.Fatalf("refused answer allows credentials: %q", got)
				}
			})
		}
	}
}

// A preflight from any other origin is refused, so a page elsewhere cannot
// learn that it may send the custom header; an allowed origin is granted
// without credentials.
func TestPreflightNeverGrantsAnotherOriginOrCredentials(t *testing.T) {
	server := newTestServer(t)
	for _, origin := range []string{"https://evil.example", "null", "chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"} {
		request := rawRequest(server, http.MethodOptions, "/v1/session", "")
		request.Header.Set("Origin", origin)
		request.Header.Set("Access-Control-Request-Method", "POST")
		request.Header.Set("Access-Control-Request-Headers", "content-type,x-dragpass-local-rpc,authorization")
		request.Header.Set("Access-Control-Request-Private-Network", "true")
		recorder := serve(server, request)
		if recorder.Code != http.StatusForbidden {
			t.Fatalf("preflight from %s: status=%d", origin, recorder.Code)
		}
		assertNoCORSGrant(t, recorder)
		if got := recorder.Header().Get("Access-Control-Allow-Private-Network"); got != "" {
			t.Fatalf("preflight from %s granted the private network: %q", origin, got)
		}
	}
	for _, origin := range []string{testOrigin, NativeExtensionOrigin} {
		request := rawRequest(server, http.MethodOptions, "/v1/session", "")
		request.Header.Set("Origin", origin)
		request.Header.Set("Access-Control-Request-Method", "POST")
		recorder := serve(server, request)
		if recorder.Code != http.StatusNoContent || recorder.Header().Get("Access-Control-Allow-Origin") != origin {
			t.Fatalf("preflight from %s: status=%d headers=%v", origin, recorder.Code, recorder.Header())
		}
		if recorder.Header().Get("Access-Control-Allow-Credentials") != "" || recorder.Header().Get("Access-Control-Allow-Origin") == "*" {
			t.Fatalf("preflight from %s: credentials or wildcard granted: %v", origin, recorder.Header())
		}
	}
}

// Every answer to an allowed origin names only that origin and never allows
// credentials: the session token rides in a header, not a cookie.
func TestAllowedOriginAnswersNeverAllowCredentials(t *testing.T) {
	server := newTestServer(t)
	session, csrf := openTestSession(t, server)
	for _, response := range []*httptest.ResponseRecorder{
		localRequest(server, http.MethodGet, "/v1/health", "", "", ""),
		localRequest(server, http.MethodPost, "/v1/session/challenge", "{}", "", ""),
		localRequest(server, http.MethodPost, "/v1/status", "{}", session, csrf),
		localRequest(server, http.MethodPost, "/v1/status", "{}", "unknown", csrf),
	} {
		if response.Header().Get("Access-Control-Allow-Origin") != testOrigin ||
			response.Header().Get("Access-Control-Allow-Credentials") != "" ||
			response.Header().Get("Vary") != "Origin" {
			t.Fatalf("status=%d headers=%v", response.Code, response.Header())
		}
	}
}

func TestPairingProofCannotBeForgedReplayedOrMoved(t *testing.T) {
	server := newTestServer(t)
	open := func(origin, body string) int {
		return localRequestFromOrigin(server, http.MethodPost, "/v1/session", body, "", "", origin).Code
	}

	// A proof made with the native proxy key: the two keys derived from the
	// local secret are not interchangeable.
	challenge := requestAppChallenge(t, server)
	if got := open(testOrigin, appOpenBody(server.secret.NativeProxyKey(), testOrigin, challenge, testClientNonce)); got != http.StatusUnauthorized {
		t.Fatalf("proof under the native proxy key=%d, want 401", got)
	}
	// A proof made for the App origin, presented from the Extension origin:
	// the proof binds the origin the session will be bound to.
	challenge = requestAppChallenge(t, server)
	if got := open(NativeExtensionOrigin, appOpenBody(server.appKey, testOrigin, challenge, testClientNonce)); got != http.StatusUnauthorized {
		t.Fatalf("proof moved to another origin=%d, want 401", got)
	}
	// A proof over another client nonce than the one sent.
	challenge = requestAppChallenge(t, server)
	moved, _ := json.Marshal(map[string]string{
		"challenge":    challenge,
		"client_nonce": testClientNonce,
		"proof":        macB64(server.appKey, appOpenLabel, testOrigin, challenge, "b3RoZXItY2xpZW50LW5vbmNlLTE2"),
	})
	if got := open(testOrigin, string(moved)); got != http.StatusUnauthorized {
		t.Fatalf("proof over another client nonce=%d, want 401", got)
	}
	// Missing, empty and malformed proofs.
	challenge = requestAppChallenge(t, server)
	for _, body := range []string{
		`{"challenge":"` + challenge + `","client_nonce":"` + testClientNonce + `"}`,
		`{"challenge":"` + challenge + `","client_nonce":"` + testClientNonce + `","proof":""}`,
		`{"challenge":"` + challenge + `","client_nonce":"` + testClientNonce + `","proof":"!!!"}`,
		`{"challenge":"` + challenge + `","client_nonce":"` + testClientNonce + `","proof":null}`,
		`[]`, `null`, `"x"`, `{`,
	} {
		if got := open(testOrigin, body); got != http.StatusUnauthorized {
			t.Fatalf("session body %s=%d, want 401", body, got)
		}
	}

	// A proof that opened a session, captured and sent again, opens nothing:
	// the challenge was consumed by the first use.
	challenge = requestAppChallenge(t, server)
	captured := appOpenBody(server.appKey, testOrigin, challenge, testClientNonce)
	if got := open(testOrigin, captured); got != http.StatusOK {
		t.Fatalf("first use of the proof=%d, want 200", got)
	}
	if got := open(testOrigin, captured); got != http.StatusUnauthorized {
		t.Fatalf("replayed proof=%d, want 401", got)
	}
}

// The response a proof earns, if a listener in the middle kept it, gives
// nothing to send requests with: the session key needs the pairing key.
func TestSessionAnswerWithoutThePairingKeySealsNothing(t *testing.T) {
	server := newTestServer(t)
	session, csrf := openTestSession(t, server)
	guessed := appSessionKey(testSecret(t).AppPairingKey(), testOrigin, "c", testClientNonce, session, csrf, 0)
	envelope, err := sealEnvelope(guessed, appRequestAAD(testOrigin, session, "/v1/status"), []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(envelope)
	if got := localRawRequest(server, http.MethodPost, "/v1/status", string(raw), session, csrf).Code; got != http.StatusForbidden {
		t.Fatalf("request sealed without the pairing key=%d, want 403", got)
	}
}

// sealFor seals body the way the App does, for session's key and path.
func sealFor(t *testing.T, server *Server, session, path, body string) (string, string) {
	t.Helper()
	server.mu.Lock()
	current := server.sessions[session]
	server.mu.Unlock()
	envelope, err := sealEnvelope(current.key, appRequestAAD(current.origin, session, path), []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(envelope)
	return string(raw), envelope.Nonce
}

// Two paired Apps (two tabs, or two browsers paired with the same Keeper)
// hold two sessions. Nothing of one is usable on the other.
func TestRequestsCannotBeSwappedBetweenSessions(t *testing.T) {
	server := newTestServer(t)
	sessionA, csrfA := openTestSession(t, server)
	sessionB, csrfB := openTestSession(t, server)

	sealedForA, _ := sealFor(t, server, sessionA, "/v1/status", "{}")
	if got := localRawRequest(server, http.MethodPost, "/v1/status", sealedForA, sessionB, csrfB).Code; got != http.StatusForbidden {
		t.Fatalf("A's envelope on session B=%d, want 403", got)
	}
	if got := localRawRequest(server, http.MethodPost, "/v1/status", sealedForA, sessionA, csrfB).Code; got != http.StatusForbidden {
		t.Fatalf("A's token with B's CSRF=%d, want 403", got)
	}
	if got := localRawRequest(server, http.MethodPost, "/v1/status", sealedForA, sessionA, "").Code; got != http.StatusForbidden {
		t.Fatalf("A's token without CSRF=%d, want 403", got)
	}
	if got := localRawRequest(server, http.MethodPost, "/v1/status", sealedForA, "", csrfA).Code; got != http.StatusUnauthorized {
		t.Fatalf("no bearer=%d, want 401", got)
	}
	// The refusals above did not burn A's envelope: it was never opened.
	if got := localRawRequest(server, http.MethodPost, "/v1/status", sealedForA, sessionA, csrfA).Code; got != http.StatusOK {
		t.Fatalf("A's envelope on A=%d, want 200", got)
	}
	// Sent again on A, it is a replay.
	if got := localRawRequest(server, http.MethodPost, "/v1/status", sealedForA, sessionA, csrfA).Code; got != http.StatusConflict {
		t.Fatalf("A's envelope replayed=%d, want 409", got)
	}

	// After A is closed, its envelopes and token are dead, and B is untouched.
	stillSealed, _ := sealFor(t, server, sessionA, "/v1/status", "{}")
	if got := localRequest(server, http.MethodDelete, "/v1/session", "", sessionA, "").Code; got != http.StatusNoContent {
		t.Fatalf("close A=%d", got)
	}
	if got := localRawRequest(server, http.MethodPost, "/v1/status", stillSealed, sessionA, csrfA).Code; got != http.StatusUnauthorized {
		t.Fatalf("A's envelope after close=%d, want 401", got)
	}
	if got := localRequest(server, http.MethodPost, "/v1/status", "{}", sessionB, csrfB).Code; got != http.StatusOK {
		t.Fatalf("B after A closed=%d, want 200", got)
	}
}

// A session opened by the Extension origin and one opened by the App origin
// are bound to their origins; neither is usable from the other.
func TestSessionsAreBoundToTheOriginThatOpenedThem(t *testing.T) {
	server := newTestServer(t)
	challenge := requestAppChallenge(t, server)
	response := localRequestFromOrigin(server, http.MethodPost, "/v1/session",
		appOpenBody(server.appKey, NativeExtensionOrigin, challenge, testClientNonce), "", "", NativeExtensionOrigin)
	if response.Code != http.StatusOK {
		t.Fatalf("open from the Extension origin=%d", response.Code)
	}
	var opened struct {
		Session string `json:"session"`
		CSRF    string `json:"csrf"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &opened); err != nil {
		t.Fatal(err)
	}
	if got := localRequestFromOrigin(server, http.MethodPost, "/v1/status", "{}", opened.Session, opened.CSRF, testOrigin).Code; got != http.StatusForbidden {
		t.Fatalf("Extension-origin session from the App origin=%d, want 403", got)
	}
	if got := localRequestFromOrigin(server, http.MethodPost, "/v1/status", "{}", opened.Session, opened.CSRF, NativeExtensionOrigin).Code; got != http.StatusOK {
		t.Fatalf("Extension-origin session from its own origin=%d, want 200", got)
	}
}

// The App opens an answer only under the AAD of its own request; an answer
// sealed to another request, route or session does not open.
func TestSealedAnswerOpensOnlyForItsOwnRequest(t *testing.T) {
	server := newTestServer(t)
	sessionA, csrfA := openTestSession(t, server)
	sessionB, _ := openTestSession(t, server)
	body, nonce := sealFor(t, server, sessionA, "/v1/status", "{}")
	response := localRawRequest(server, http.MethodPost, "/v1/status", body, sessionA, csrfA)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d", response.Code)
	}
	var answer sealedEnvelope
	if err := json.Unmarshal(response.Body.Bytes(), &answer); err != nil {
		t.Fatal(err)
	}
	server.mu.Lock()
	keyA, keyB := server.sessions[sessionA].key, server.sessions[sessionB].key
	server.mu.Unlock()
	if _, err := openEnvelope(keyA, answer, appResponseAAD(testOrigin, sessionA, "/v1/status", nonce)); err != nil {
		t.Fatalf("the answer does not open for its own request: %v", err)
	}
	for name, attempt := range map[string]func() error{
		"another request nonce": func() error {
			_, err := openEnvelope(keyA, answer, appResponseAAD(testOrigin, sessionA, "/v1/status", "AAAAAAAAAAAAAAAA"))
			return err
		},
		"another route": func() error {
			_, err := openEnvelope(keyA, answer, appResponseAAD(testOrigin, sessionA, "/v1/message/display", nonce))
			return err
		},
		"another origin": func() error {
			_, err := openEnvelope(keyA, answer, appResponseAAD(NativeExtensionOrigin, sessionA, "/v1/status", nonce))
			return err
		},
		"another session": func() error {
			_, err := openEnvelope(keyB, answer, appResponseAAD(testOrigin, sessionB, "/v1/status", nonce))
			return err
		},
		"opened as a request": func() error {
			_, err := openEnvelope(keyA, answer, appRequestAAD(testOrigin, sessionA, "/v1/status"))
			return err
		},
	} {
		if attempt() == nil {
			t.Fatalf("the answer opened for %s", name)
		}
	}
}

func TestMalformedSealedEnvelopesAreRefused(t *testing.T) {
	server := newTestServer(t)
	session, csrf := openTestSession(t, server)
	good, _ := sealFor(t, server, session, "/v1/status", "{}")
	assertMalformedEnvelopesRefused(t, server, session, csrf, good)
}

// An earlier "A"+ct[1:] tamper left the ciphertext unchanged whenever it
// already started with "A" (about 1 run in 64). Force that case: the bit
// flip must still change the ciphertext and the envelope must be refused.
func TestFlippedCiphertextStartingWithAIsRefused(t *testing.T) {
	server := newTestServer(t)
	session, csrf := openTestSession(t, server)
	for attempt := 0; attempt < 10_000; attempt++ {
		good, _ := sealFor(t, server, session, "/v1/status", "{}")
		var envelope map[string]any
		if err := json.Unmarshal([]byte(good), &envelope); err != nil {
			t.Fatal(err)
		}
		if ct, _ := envelope["ct"].(string); strings.HasPrefix(ct, "A") {
			assertMalformedEnvelopesRefused(t, server, session, csrf, good)
			return
		}
	}
	t.Fatal("no sealed envelope with a ciphertext starting with A in 10000 attempts")
}

// flipCiphertextBit returns ct with the low bit of its first decoded byte
// flipped, so the result always differs from ct and stays valid base64url.
func flipCiphertextBit(t *testing.T, ct string) string {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(ct)
	if err != nil || len(raw) == 0 {
		t.Fatalf("ciphertext %q is not non-empty base64url: %v", ct, err)
	}
	raw[0] ^= 0x01
	return base64.RawURLEncoding.EncodeToString(raw)
}

func assertMalformedEnvelopesRefused(t *testing.T, server *Server, session, csrf, good string) {
	t.Helper()
	var envelope map[string]any
	if err := json.Unmarshal([]byte(good), &envelope); err != nil {
		t.Fatal(err)
	}
	with := func(key string, value any) string {
		copied := map[string]any{}
		for k, v := range envelope {
			copied[k] = v
		}
		if value == nil {
			delete(copied, key)
		} else {
			// A tamper that reproduces the original value would send
			// the good envelope and test nothing.
			if original, ok := envelope[key]; ok && fmt.Sprint(original) == fmt.Sprint(value) {
				t.Fatalf("tampered %s equals the original %v", key, original)
			}
			copied[key] = value
		}
		raw, _ := json.Marshal(copied)
		return string(raw)
	}
	nonce, _ := envelope["nonce"].(string)
	ct, _ := envelope["ct"].(string)
	for name, body := range map[string]string{
		"proxy-shaped with instance":  with("instance", "owner"),
		"proxy-shaped with timestamp": with("ts", time.Now().Unix()),
		"unknown field":               with("action", "group_dek_export"),
		"no nonce":                    with("nonce", nil),
		"no ciphertext":               with("ct", nil),
		"short nonce":                 with("nonce", "AAAA"),
		"truncated ciphertext":        with("ct", ct[:len(ct)-4]),
		"flipped ciphertext":          with("ct", flipCiphertextBit(t, ct)),
		"nonce not base64url":         with("nonce", nonce[:len(nonce)-1]+"+"),
		"not json":                    "action=status",
		"json array":                  "[" + good + "]",
		"empty":                       "",
	} {
		if got := localRawRequest(server, http.MethodPost, "/v1/status", body, session, csrf).Code; got != http.StatusForbidden && got != http.StatusUnsupportedMediaType {
			t.Fatalf("%s: status=%d, want 403", name, got)
		}
	}
	// None of the refusals consumed the good envelope.
	if got := localRawRequest(server, http.MethodPost, "/v1/status", good, session, csrf).Code; got != http.StatusOK {
		t.Fatalf("good envelope after the malformed ones=%d, want 200", got)
	}
}

// Only POST with exactly application/json reaches a route; other methods
// find nothing, so a form post or a simple request cannot run an action.
func TestMethodAndContentTypeConfusionIsRefused(t *testing.T) {
	server := newTestServer(t)
	session, csrf := openTestSession(t, server)
	for _, contentType := range []string{"", "text/plain", "text/plain;charset=UTF-8", "application/x-www-form-urlencoded",
		"multipart/form-data; boundary=x", "application/json; charset=utf-8", "APPLICATION/JSON", "application/json-patch+json"} {
		for _, path := range []string{"/v1/session/challenge", "/v1/session", "/v1/status", "/v1/native-proxy/message"} {
			request := rawRequest(server, http.MethodPost, path, "{}")
			if strings.HasPrefix(path, "/v1/native-proxy") {
				request.Header.Set("Origin", NativeExtensionOrigin)
			}
			request.Header.Set("Authorization", "Bearer "+session)
			request.Header.Set("X-DragPass-CSRF", csrf)
			if contentType == "" {
				request.Header.Del("Content-Type")
			} else {
				request.Header.Set("Content-Type", contentType)
			}
			if got := serve(server, request).Code; got != http.StatusUnsupportedMediaType {
				t.Fatalf("POST %s as %q=%d, want 415", path, contentType, got)
			}
		}
	}
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodPatch, http.MethodHead} {
		for _, path := range []string{"/v1/session/challenge", "/v1/session", "/v1/status", "/v1/request-signature",
			"/v1/message/display", "/v1/chat/mls_room_name_open", "/v1/native-proxy/message"} {
			request := rawRequest(server, method, path, "")
			if strings.HasPrefix(path, "/v1/native-proxy") {
				request.Header.Set("Origin", NativeExtensionOrigin)
			}
			request.Header.Set("Authorization", "Bearer "+session)
			request.Header.Set("X-DragPass-CSRF", csrf)
			if got := serve(server, request).Code; got != http.StatusNotFound {
				t.Fatalf("%s %s=%d, want 404", method, path, got)
			}
		}
	}
	// Path tricks do not reach a route either.
	for _, path := range []string{"/v1/status/", "/v1//status", "/V1/status", "/v1/status%2F", "/v1/./status", "/v1/action/ping"} {
		request := rawRequest(server, http.MethodPost, path, "{}")
		request.Header.Set("Authorization", "Bearer "+session)
		request.Header.Set("X-DragPass-CSRF", csrf)
		if got := serve(server, request).Code; got != http.StatusNotFound {
			t.Fatalf("POST %s=%d, want 404", path, got)
		}
	}
}

// The body cap is applied before anything is parsed, on the routes that need
// no session too.
func TestOversizedBodiesAreRefusedBeforeParsing(t *testing.T) {
	server := newTestServer(t)
	session, csrf := openTestSession(t, server)
	big := `{"pad":"` + strings.Repeat("x", 3*maxRequestBytes) + `"}`
	for _, path := range []string{"/v1/session/challenge", "/v1/session", "/v1/status", "/v1/request-signature"} {
		request := rawRequest(server, http.MethodPost, path, big)
		request.Header.Set("Authorization", "Bearer "+session)
		request.Header.Set("X-DragPass-CSRF", csrf)
		if got := serve(server, request).Code; got != http.StatusBadRequest {
			t.Fatalf("oversized POST %s=%d, want 400", path, got)
		}
	}
}

// Anyone who can reach the port can ask for challenges; the pending set is
// capped, so the worst they do is delay a session by the challenge lifetime
// (accepted: a port squatter can already deny service).
func TestPendingChallengesAreCapped(t *testing.T) {
	server := newTestServer(t)
	for i := range maxAppChallenges {
		if got := localRequest(server, http.MethodPost, "/v1/session/challenge", "{}", "", "").Code; got != http.StatusOK {
			t.Fatalf("challenge %d=%d", i, got)
		}
	}
	if got := localRequest(server, http.MethodPost, "/v1/session/challenge", "{}", "", "").Code; got != http.StatusTooManyRequests {
		t.Fatalf("challenge over the cap=%d, want 429", got)
	}
	server.now = func() time.Time { return time.Unix(1_800_000_000, 0).Add(appChallengeTTL) }
	if got := localRequest(server, http.MethodPost, "/v1/session/challenge", "{}", "", "").Code; got != http.StatusOK {
		t.Fatalf("challenge after the old ones expired=%d, want 200", got)
	}
}

// A paired caller cannot hold more than 64 live sessions.
func TestLiveSessionsAreCapped(t *testing.T) {
	server := newTestServer(t)
	for range 64 {
		openTestSession(t, server)
	}
	challenge := requestAppChallenge(t, server)
	if got := localRequest(server, http.MethodPost, "/v1/session", appOpenBody(server.appKey, testOrigin, challenge, testClientNonce), "", "").Code; got != http.StatusTooManyRequests {
		t.Fatalf("session over the cap=%d, want 429", got)
	}
}

// The native proxy channel takes only messages sealed under the proxy key to
// this owner instance within the clock window; the App pairing key and an
// App session do not open it.
func TestNativeProxyChannelIsSeparateFromTheAppChannel(t *testing.T) {
	server := newTestServer(t)
	proxied := func(body string) int {
		return localRequestFromOrigin(server, http.MethodPost, "/v1/native-proxy/message", body, "", "", NativeExtensionOrigin).Code
	}
	underAppKey, _ := sealedPing(t, server.appKey, server.proxy.instance, server.now())
	if got := proxied(underAppKey); got != http.StatusForbidden {
		t.Fatalf("proxy message sealed under the App pairing key=%d, want 403", got)
	}
	for _, skew := range []time.Duration{-61 * time.Second, 61 * time.Second} {
		body, _ := sealedPing(t, server.proxy.key, server.proxy.instance, server.now().Add(skew))
		if got := proxied(body); got != http.StatusForbidden {
			t.Fatalf("proxy message %v off the clock=%d, want 403", skew, got)
		}
	}
	// The proxy health proof is useless as an App proof and the other way
	// round: different keys and labels.
	const challenge = "cHJveHktY2hhbGxlbmdlLTE2Yg"
	appChallenge := requestAppChallenge(t, server)
	forged, _ := json.Marshal(map[string]string{
		"challenge":    appChallenge,
		"client_nonce": challenge,
		"proof":        macB64(server.proxy.key, appOpenLabel, testOrigin, appChallenge, challenge),
	})
	if got := localRequest(server, http.MethodPost, "/v1/session", string(forged), "", "").Code; got != http.StatusUnauthorized {
		t.Fatalf("App proof under the proxy key=%d, want 401", got)
	}
	// An App session's credentials do not authenticate the proxy route.
	session, csrf := openTestSession(t, server)
	sealed, _ := sealFor(t, server, session, "/v1/native-proxy/message", `{"action":"ping"}`)
	request := rawRequest(server, http.MethodPost, "/v1/native-proxy/message", sealed)
	request.Header.Set("Origin", NativeExtensionOrigin)
	request.Header.Set("Authorization", "Bearer "+session)
	request.Header.Set("X-DragPass-CSRF", csrf)
	if got := serve(server, request).Code; got != http.StatusForbidden {
		t.Fatalf("App-session envelope on the proxy route=%d, want 403", got)
	}
}

// The request-signature nonce set is per session: a signature request
// captured on one session is refused there, and a different session cannot
// be handed the same envelope.
func TestSigningRequestReplayAcrossSessions(t *testing.T) {
	server := newTestServer(t)
	generated, _ := json.Marshal(map[string]string{"action": "request_key_generate"})
	if response := server.app.HandleRequest(generated); !response.Success {
		t.Fatalf("request key generation failed: %+v", response)
	}
	sessionA, csrfA := openTestSession(t, server)
	sessionB, csrfB := openTestSession(t, server)
	body := fmt.Sprintf(`{"method":"POST","path":"/api/v1/account/devices","query":"","timestamp":"%d","nonce":"AAAAAAAAAAAAAAAAAAAAAA","body_sha256":"%064d","account_id":"11111111-1111-4111-8111-111111111111","token_id":"22222222-2222-4222-8222-222222222222","device_id":"device-12345678"}`, server.now().Unix(), 0)
	sealedA, _ := sealFor(t, server, sessionA, "/v1/request-signature", body)
	if got := localRawRequest(server, http.MethodPost, "/v1/request-signature", sealedA, sessionB, csrfB).Code; got != http.StatusForbidden {
		t.Fatalf("A's signing envelope on B=%d, want 403", got)
	}
	if got := localRawRequest(server, http.MethodPost, "/v1/request-signature", sealedA, sessionA, csrfA).Code; got != http.StatusOK {
		t.Fatalf("A's signing envelope on A=%d, want 200", got)
	}
	resealed, _ := sealFor(t, server, sessionA, "/v1/request-signature", body)
	if got := localRawRequest(server, http.MethodPost, "/v1/request-signature", resealed, sessionA, csrfA).Code; got != http.StatusConflict {
		t.Fatalf("the same signing nonce resealed on A=%d, want 409", got)
	}
	stale := strings.Replace(body, fmt.Sprintf(`"%d"`, server.now().Unix()), fmt.Sprintf(`"%d"`, server.now().Unix()-61), 1)
	if stale == body {
		t.Fatal("the stale timestamp replacement changed nothing")
	}
	reNonced := strings.Replace(stale, "AAAAAAAAAAAAAAAAAAAAAA", "BBBBBBBBBBBBBBBBBBBBBB", 1)
	if reNonced == stale {
		t.Fatal("the nonce replacement changed nothing")
	}
	stale = reNonced
	if got := localRequest(server, http.MethodPost, "/v1/request-signature", stale, sessionB, csrfB).Code; got != http.StatusBadRequest {
		t.Fatalf("stale signing timestamp=%d, want 400", got)
	}
}

// The pin owner Keeper recorded first holds for every App session: a second
// session, or the same one, naming another account is refused before any pin
// is read, and no App route can clear the record.
func TestAppSessionsCannotSwitchThePinOwner(t *testing.T) {
	server := newTestServer(t)
	sessionA, csrfA := openTestSession(t, server)
	sessionB, csrfB := openTestSession(t, server)
	const otherOwner = "33333333-3333-4333-8333-333333333333"
	if code, result, body := callRoute(t, server, sessionA, csrfA, "/v1/peer-key/pin-list", map[string]string{"owner_account_id": routeOwner}); code != http.StatusOK || !result.Success {
		t.Fatalf("first owner: %d %s", code, body)
	}
	for _, s := range []struct{ session, csrf string }{{sessionA, csrfA}, {sessionB, csrfB}} {
		for path, request := range map[string]any{
			"/v1/peer-key/pin-list": map[string]string{"owner_account_id": otherOwner},
			"/v1/peer-key/pin":      map[string]string{"owner_account_id": otherOwner, "account_id": routePeer},
		} {
			code, result, body := callRoute(t, server, s.session, s.csrf, path, request)
			if code != http.StatusOK || result.Success || result.ErrorCode != "peer_key_owner_mismatch" {
				t.Fatalf("%s with another owner: %d %s", path, code, body)
			}
		}
	}
	for _, path := range []string{"/v1/peer-key/owner-reset", "/v1/peer-key/peer_key_owner_reset", "/v1/chat/peer_key_owner_reset"} {
		if got := localRequest(server, http.MethodPost, path, "{}", sessionA, csrfA).Code; got != http.StatusNotFound {
			t.Fatalf("%s=%d, want 404", path, got)
		}
	}
}
