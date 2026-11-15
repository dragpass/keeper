package keystore

import (
	"encoding/json"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/proto"
)

// The Extension keeps its device-wide archive_key_generate over Native
// Messaging (its E2E org fixture). The org-scoped form is the App's: a
// Native frame that names an org is refused before the handler, so an
// Extension or a proxied host cannot create org slots (lv96).
func TestNativeArchiveKeyGenerateWithOrgIsRefused(t *testing.T) {
	app, _, store := newLeaseApp(t)
	frame := func(payload string) []byte {
		b, _ := json.Marshal(map[string]any{"action": proto.ActionArchiveKeyGenerate, "request_id": "g", "payload": json.RawMessage(payload)})
		return b
	}
	before := store.calls.Load()
	refused := app.HandleRequest(frame(`{"org_id":"33333333-3333-4333-8333-333333333333"}`))
	if refused.Success || refused.ErrorCode != ErrCodeChatAppCallerRequired || refused.RequestID != "g" {
		t.Fatalf("org-scoped generate over Native Messaging: %+v", refused)
	}
	if store.calls.Load() != before {
		t.Fatal("a refused Native org generate touched the keychain")
	}
	if device := app.HandleRequest(frame(`{}`)); !device.Success {
		t.Fatalf("device-wide generate over Native Messaging: %+v", device)
	}
	if org := app.HandleAppRequest(sessionA, "", frame(`{"org_id":"33333333-3333-4333-8333-333333333333"}`)); !org.Success {
		t.Fatalf("org generate from the App: %+v", org)
	}
}
