package localrpc

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/handlers"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

const (
	refreshTestBinding = "-B5iTp-AXzAzRyRT3PzNPt9ukdY5HYIabH8Lc3Gyquk"
	refreshTestBody    = "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
	refreshTestDevice  = "33333333-3333-4333-8333-333333333333"
)

func refreshSignatureBody(server *Server, nonce, extra string) string {
	return fmt.Sprintf(`{"timestamp":"%d","nonce":"%s","body_sha256":"%s","app_binding":"%s","device_id":"%s"%s}`,
		server.now().Unix(), nonce, refreshTestBody, refreshTestBinding, refreshTestDevice, extra)
}

// The route signs dp-app-refresh-v1 over the paired session's origin; the App
// cannot name another origin, and a nonce is signed once per session.
func TestLocalRPCSignsAppSessionRefreshForTheSessionOrigin(t *testing.T) {
	server := newTestServer(t)
	generated, _ := json.Marshal(map[string]string{"action": "request_key_generate"})
	if response := server.app.HandleRequest(generated); !response.Success {
		t.Fatalf("request key generation failed: %+v", response)
	}
	publicB64, err := keychain.GetRequestSigningPublicKey(server.app.Store)
	if err != nil {
		t.Fatal(err)
	}
	public, _ := base64.StdEncoding.DecodeString(publicB64)
	session, csrf := openTestSession(t, server)

	body := refreshSignatureBody(server, "AAAAAAAAAAAAAAAAAAAAAA", "")
	first := localRequest(server, http.MethodPost, "/v1/app-session-refresh-signature", body, session, csrf)
	if first.Code != http.StatusOK {
		t.Fatalf("sign refresh: status=%d body=%s", first.Code, first.Body.String())
	}
	var result struct {
		Success bool                          `json:"success"`
		Data    proto.SignRequestResponseData `json:"data"`
	}
	if err := json.Unmarshal(first.Body.Bytes(), &result); err != nil || !result.Success {
		t.Fatalf("invalid keeper response: body=%s err=%v", first.Body.String(), err)
	}
	canonical := handlers.AppSessionRefreshCanonical(proto.SignAppSessionRefreshRequest{
		Origin: testOrigin, Timestamp: fmt.Sprint(server.now().Unix()), Nonce: "AAAAAAAAAAAAAAAAAAAAAA",
		BodySHA256: refreshTestBody, AppBinding: refreshTestBinding, DeviceID: refreshTestDevice,
	})
	signature, _ := base64.StdEncoding.DecodeString(result.Data.Signature)
	if !ed25519.Verify(public, []byte(canonical), signature) {
		t.Fatal("signature does not verify over the canonical with the session origin")
	}

	if got := localRequest(server, http.MethodPost, "/v1/app-session-refresh-signature", body, session, csrf).Code; got != http.StatusConflict {
		t.Fatalf("replayed nonce status=%d, want 409", got)
	}
	withOrigin := refreshSignatureBody(server, "BBBBBBBBBBBBBBBBBBBBBB", `,"origin":"https://evil.example"`)
	if got := localRequest(server, http.MethodPost, "/v1/app-session-refresh-signature", withOrigin, session, csrf).Code; got != http.StatusBadRequest {
		t.Fatalf("caller-named origin status=%d, want 400", got)
	}
	stale := fmt.Sprintf(`{"timestamp":"%d","nonce":"CCCCCCCCCCCCCCCCCCCCCC","body_sha256":"%s","app_binding":"%s","device_id":"%s"}`,
		server.now().Unix()-61, refreshTestBody, refreshTestBinding, refreshTestDevice)
	if got := localRequest(server, http.MethodPost, "/v1/app-session-refresh-signature", stale, session, csrf).Code; got != http.StatusBadRequest {
		t.Fatalf("stale timestamp status=%d, want 400", got)
	}
	if got := localRequest(server, http.MethodPost, "/v1/app-session-refresh-signature", body, "", "").Code; got != http.StatusUnauthorized {
		t.Fatalf("no session status=%d, want 401", got)
	}
}
