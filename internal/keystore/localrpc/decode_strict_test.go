package localrpc

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
)

// The signing request is decoded like every other App request: one JSON
// object with only the canonical's fields.
func TestRequestSignatureRefusesAnUnknownField(t *testing.T) {
	server := newTestServer(t)
	generated, _ := json.Marshal(map[string]string{"action": "request_key_generate"})
	if response := server.app.HandleRequest(generated); !response.Success {
		t.Fatalf("request key generation failed: %+v", response)
	}
	session, csrf := openTestSession(t, server)
	body := func(extra string) string {
		return fmt.Sprintf(`{"method":"GET","path":"/api/v1/account/me","query":"","timestamp":"%d","nonce":"AAAAAAAAAAAAAAAAAAAAAA","body_sha256":"%064d","account_id":"11111111-1111-4111-8111-111111111111","token_id":"22222222-2222-4222-8222-222222222222","device_id":"device-12345678"%s}`,
			server.now().Unix(), 0, extra)
	}
	if code := localRequest(server, http.MethodPost, "/v1/request-signature", body(`,"canonical_request":"x"`), session, csrf).Code; code != http.StatusBadRequest {
		t.Fatalf("an unknown field was signed: %d", code)
	}
	if code := localRequest(server, http.MethodPost, "/v1/request-signature", body(""), session, csrf).Code; code != http.StatusOK {
		t.Fatalf("the canonical fields alone: %d", code)
	}
}

func TestOpenSessionRefusesTrailingJSON(t *testing.T) {
	server := newTestServer(t)
	challenge := requestAppChallenge(t, server)
	body := appOpenBody(server.appKey, testOrigin, challenge, testClientNonce) + "{}"
	if code := localRequest(server, http.MethodPost, "/v1/session", body, "", "").Code; code != http.StatusUnauthorized {
		t.Fatalf("a session open with trailing JSON: %d", code)
	}
}

// The sealed envelope is the request body of every session route, so it too
// is exactly one JSON object: bytes after it are refused, not ignored.
func TestSealedEnvelopeRefusesTrailingData(t *testing.T) {
	server := newTestServer(t)
	session, csrf := openTestSession(t, server)
	server.mu.Lock()
	key := server.sessions[session].key
	server.mu.Unlock()
	seal := func() string {
		envelope, err := sealEnvelope(key, appRequestAAD(testOrigin, session, "/v1/status"), []byte(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(envelope)
		return string(raw)
	}
	for _, trailing := range []string{"{}", seal(), `"x"`, "garbage"} {
		if code := localRawRequest(server, http.MethodPost, "/v1/status", seal()+trailing, session, csrf).Code; code != http.StatusForbidden {
			t.Fatalf("an envelope followed by %q: %d, want 403", trailing, code)
		}
	}
	if code := localRawRequest(server, http.MethodPost, "/v1/status", seal()+"\n", session, csrf).Code; code != http.StatusOK {
		t.Fatalf("an envelope with a trailing newline: %d, want 200", code)
	}
}
