package localrpc

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"sync"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// Every action payload a route builds or forwards (the App's own bytes, a
// re-encoding, a composed step's request) is wiped once its action returns:
// the password change carries both passwords through two of them.
func TestRoutePayloadsAreWipedAfterTheirActions(t *testing.T) {
	server := newTestServer(t)
	if err := keychain.SaveDeviceKey(server.app.Store, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x5a}, 32))); err != nil {
		t.Fatal(err)
	}
	current := passwordWrap(t, "current-password", bytes.Repeat([]byte{0x22}, 32))
	session, csrf := openTestSession(t, server)
	var mu sync.Mutex
	var payloads [][]byte
	server.onAction = func(_ string, payload []byte, _ proto.BaseResponse) {
		mu.Lock()
		payloads = append(payloads, payload)
		mu.Unlock()
	}

	code, result, body := callRoute(t, server, session, csrf, "/v1/auth/password/rewrap", map[string]string{
		"password": "current-password", "encrypted_dek_b64": current, "new_password": "new-password",
	})
	if code != http.StatusOK || !result.Success {
		t.Fatalf("rewrap: %d %s", code, body)
	}
	code, result, body = callRoute(t, server, session, csrf, "/v1/auth/login/sign-alias", map[string]string{"alias": "alice"})
	if code != http.StatusOK {
		t.Fatalf("sign-alias: %d %s", code, body)
	}
	if len(payloads) != 3 {
		t.Fatalf("observed %d actions", len(payloads))
	}
	for i, payload := range payloads {
		if len(payload) == 0 || !bytes.Equal(payload, make([]byte, len(payload))) {
			t.Fatalf("payload %d outlived its action: %q", i, payload)
		}
	}
}
