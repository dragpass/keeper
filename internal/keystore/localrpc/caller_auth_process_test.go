package localrpc

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/dragpass/keeper/internal/keystore/dispatch"
)

// rawLocalCall is what a local process that is not the App sends: any
// headers it likes, no pairing key.
func rawLocalCall(t *testing.T, address, method, path, body string, headers map[string]string, host string) (*http.Response, string) {
	t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	request, err := http.NewRequest(method, "http://"+address+path, reader)
	if err != nil {
		t.Fatal(err)
	}
	if host != "" {
		request.Host = host
	}
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}}
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer response.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(response.Body, 1<<16))
	return response, string(raw)
}

func browserHeaders(origin string) map[string]string {
	return map[string]string{
		"Origin":               origin,
		"Sec-Fetch-Site":       "cross-site",
		"X-DragPass-Local-RPC": "1",
		"Content-Type":         "application/json",
	}
}

// The release entry point as the owner, and a same-machine process without
// the pairing key: it can set every browser header, but it opens no session,
// runs no session route, and the owner keeps serving the paired App.
func TestUnpairedLocalProcessIsRefusedByARealOwner(t *testing.T) {
	dir, address := t.TempDir(), freeLoopbackAddress(t)
	owner := startAppService(t, dir, address)

	refused := []struct {
		name   string
		origin string
		host   string
	}{
		{"another site", "https://evil.example", ""},
		{"null origin", "null", ""},
		{"another extension", "chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ""},
		{"rebinding host", testOrigin, "evil.example:" + strings.Split(address, ":")[1]},
		{"localhost host", testOrigin, "localhost:" + strings.Split(address, ":")[1]},
	}
	for _, c := range refused {
		for _, path := range []string{"/v1/health", "/v1/session/challenge", "/v1/session", "/v1/status"} {
			method := http.MethodPost
			if path == "/v1/health" {
				method = http.MethodGet
			}
			response, _ := rawLocalCall(t, address, method, path, "{}", browserHeaders(c.origin), c.host)
			if response.StatusCode != http.StatusForbidden {
				t.Fatalf("%s %s=%d, want 403", c.name, path, response.StatusCode)
			}
			if granted := response.Header.Get("Access-Control-Allow-Origin"); granted != "" && granted != testOrigin {
				t.Fatalf("%s %s granted %q", c.name, path, granted)
			}
			if response.Header.Get("Access-Control-Allow-Credentials") != "" {
				t.Fatalf("%s %s allowed credentials", c.name, path)
			}
		}
	}

	// Forged App headers get a challenge (anyone can ask for one) and
	// nothing else.
	guessed := make([]byte, 32)
	if _, err := rand.Read(guessed); err != nil {
		t.Fatal(err)
	}
	intruder := &testAppClient{address: address, origin: testOrigin, pairingKey: guessed}
	if err := intruder.open(); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("an unpaired process opened a session: %v", err)
	}
	for _, token := range []string{"", base64.RawURLEncoding.EncodeToString(guessed)} {
		headers := browserHeaders(testOrigin)
		headers["Authorization"] = "Bearer " + token
		headers["X-DragPass-CSRF"] = token
		for _, path := range []string{"/v1/status", "/v1/request-signature", "/v1/message/display", "/v1/chat/mls_room_name_open", "/v1/auth/recovery/begin"} {
			response, body := rawLocalCall(t, address, http.MethodPost, path, `{"nonce":"AAAAAAAAAAAAAAAA","ct":"AAAA"}`, headers, "")
			if response.StatusCode != http.StatusUnauthorized {
				t.Fatalf("session route %s with token %q=%d %s, want 401", path, token, response.StatusCode, body)
			}
		}
		if response, _ := rawLocalCall(t, address, http.MethodDelete, "/v1/session", "", headers, ""); response.StatusCode != http.StatusNoContent {
			t.Fatalf("closing an unknown session=%d", response.StatusCode)
		}
	}
	// The proxy channel answers its health probe to anyone (the proof is
	// useless without the key) and runs nothing unsealed.
	proxyHeaders := browserHeaders(NativeExtensionOrigin)
	if response, body := rawLocalCall(t, address, http.MethodPost, "/v1/native-proxy/message", `{"action":"ping"}`, proxyHeaders, ""); response.StatusCode != http.StatusForbidden {
		t.Fatalf("unsealed proxy message=%d %s, want 403", response.StatusCode, body)
	}

	client := &testAppClient{address: address, origin: testOrigin, pairingKey: pairingKeyOf(t, dir)}
	if err := client.open(); err != nil {
		t.Fatalf("the paired App after the intruder: %v\n%s", err, owner.stderr.String())
	}
	if status, err := client.status(); err != nil || !status.Success {
		t.Fatalf("the paired App's status: %+v %v", status, err)
	}
}

// Every App-only action is refused to a Native Messaging frame in each role a
// Chrome-launched Keeper can take: the owner serving its own stdio, a proxy
// to a proven owner, and a standalone host next to an owner it cannot prove.
// The caller is known from the transport, so nothing in the frame changes it.
func TestNativeMessagingFramesAreRefusedEveryAppOnlyActionInEveryRole(t *testing.T) {
	appOnly := dispatch.AppOnlyActions()
	if len(appOnly) == 0 {
		t.Fatal("no App-only actions")
	}
	refusesAll := func(t *testing.T, host *nativeHost) {
		t.Helper()
		if ping := host.send(t, `{"action":"ping","request_id":"p"}`); !ping.Success {
			t.Fatalf("ping: %+v\n%s", ping, host.stderr.String())
		}
		for _, action := range appOnly {
			// The frame claims to be the App every way a frame could.
			frame := `{"action":"` + action + `","request_id":"r","caller":"app","origin":"` + testOrigin + `","payload":{}}`
			refused := host.send(t, frame)
			if refused.Success || refused.ErrorCode != "chat_app_caller_required" || refused.RequestID != "r" {
				t.Fatalf("%s from Native Messaging: %+v", action, refused)
			}
		}
	}

	t.Run("owner stdio", func(t *testing.T) {
		dir, address := t.TempDir(), freeLoopbackAddress(t)
		refusesAll(t, startNativeHost(t, dir, address))
	})
	t.Run("proxy", func(t *testing.T) {
		dir, address := t.TempDir(), freeLoopbackAddress(t)
		owner := startAppService(t, dir, address)
		refusesAll(t, startNativeHost(t, dir, address))
		if !strings.Contains(owner.stderr.String(), "received action: ping") {
			t.Fatalf("the frames did not reach the owner:\n%s", owner.stderr.String())
		}
	})
	t.Run("standalone", func(t *testing.T) {
		ownerDir, hostDir, address := t.TempDir(), t.TempDir(), freeLoopbackAddress(t)
		startAppService(t, ownerDir, address)
		host := startNativeHost(t, hostDir, address)
		refusesAll(t, host)
		if !strings.Contains(host.stderr.String(), "running standalone") {
			t.Fatalf("the host did not run standalone:\n%s", host.stderr.String())
		}
	})
}

// Malformed frames from the Native Messaging side are answered as errors and
// the host keeps serving; none of them reaches a handler.
func TestNativeMessagingMalformedFramesAreRefused(t *testing.T) {
	dir, address := t.TempDir(), freeLoopbackAddress(t)
	host := startNativeHost(t, dir, address)
	for frame, code := range map[string]string{
		`not json`:                          "validation_error",
		`[]`:                                "validation_error",
		`{"action":"no_such_action"}`:       "unsupported",
		`{"action":"PING"}`:                 "unsupported",
		`{"action":"ping ","request_id":1}`: "validation_error",
		`{"payload":{}}`:                    "unsupported",
	} {
		answer := host.send(t, frame)
		if answer.Success || answer.ErrorCode != code {
			t.Fatalf("frame %s: %+v, want %s", frame, answer, code)
		}
	}
	if ping := host.send(t, `{"action":"ping"}`); !ping.Success {
		t.Fatalf("ping after malformed frames: %+v", ping)
	}
	if bytes.Contains(host.stderr.Bytes(), []byte("panic")) {
		t.Fatalf("host panicked:\n%s", host.stderr.String())
	}
}
