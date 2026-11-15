package localrpc

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/proto"
)

// The App names the org when it creates or enables an org archive key
// (lv96); the route must pass org_id through and answer the org's own key.
func TestArchiveKeyGenerateRouteTakesOrgID(t *testing.T) {
	server, _ := newChatTestServer(t)
	session, csrf := openTestSession(t, server)
	const orgID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"

	code, device, body := callRoute(t, server, session, csrf, "/v1/archive/archive_key_generate", map[string]any{})
	if code != http.StatusOK || !device.Success {
		t.Fatalf("device-wide generate: %d %s", code, body)
	}
	code, org, body := callRoute(t, server, session, csrf, "/v1/archive/archive_key_generate", map[string]any{"org_id": orgID})
	if code != http.StatusOK || !org.Success {
		t.Fatalf("org generate: %d %s", code, body)
	}
	var d, o proto.ArchiveKeyGenerateResponseData
	_ = json.Unmarshal(device.Data, &d)
	_ = json.Unmarshal(org.Data, &o)
	if o.Scope != "org" || o.Fingerprint == d.Fingerprint {
		t.Fatalf("org generate answered %+v", o)
	}
	if code, bad, _ := callRoute(t, server, session, csrf, "/v1/archive/archive_key_generate", map[string]any{"org_id": "nope"}); bad.Success || bad.Data != nil {
		t.Fatalf("a malformed org_id was not refused: %d", code)
	}
}
