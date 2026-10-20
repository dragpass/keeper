package keystore

import (
	"encoding/json"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/proto"
)

// appBoundActions serve only the App's own surfaces: the signature of its
// cookie session refresh (bound to the paired session's origin) and the
// Secure Message display, the approved plaintext carve-out for the App's
// screen. The only callers are the App's Local RPC routes
// (/v1/app-session-refresh-signature, /v1/message/display-prepare,
// /v1/message/display); no Extension or MCP code sends them.
var appBoundActions = []string{
	proto.ActionSignAppSessionRefresh,
	proto.ActionMessageDisplayPrepare,
	proto.ActionGroupDecryptWithAadForAppDisplay,
}

// A Native Messaging frame (the Extension, another host proxying to this
// owner, or any same-user process that starts Keeper on stdio) names the
// origin itself, so over Native Messaging the refresh signature could be had
// for any origin, and the display decrypt would hand plaintext to a caller
// that is not the App.
func TestAppBoundActionsAreRefusedOnNativeMessagingAndRunNothing(t *testing.T) {
	app, _, store := newLeaseApp(t)
	if generated := app.HandleRequest([]byte(`{"action":"request_key_generate"}`)); !generated.Success {
		t.Fatalf("request key: %+v", generated)
	}
	payloads := map[string]string{
		proto.ActionSignAppSessionRefresh: `{"origin":"https://evil.example","timestamp":"1800000000",` +
			`"nonce":"AAECAwQFBgcICQoLDA0ODw","body_sha256":"44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",` +
			`"app_binding":"-B5iTp-AXzAzRyRT3PzNPt9ukdY5HYIabH8Lc3Gyquk","device_id":"33333333-3333-4333-8333-333333333333"}`,
		proto.ActionMessageDisplayPrepare:            `{}`,
		proto.ActionGroupDecryptWithAadForAppDisplay: `{}`,
	}
	for _, action := range appBoundActions {
		before := store.calls.Load()
		frame, _ := json.Marshal(map[string]any{"action": action, "request_id": "x", "payload": json.RawMessage(payloads[action])})
		response := app.HandleRequest(frame)
		if response.Success || response.ErrorCode != ErrCodeChatAppCallerRequired || response.RequestID != "x" {
			t.Fatalf("%s from Native Messaging: %+v", action, response)
		}
		if store.calls.Load() != before {
			t.Fatalf("%s ran although it was refused", action)
		}
	}
}

func TestAppBoundActionsReachTheirHandlerFromTheApp(t *testing.T) {
	app, _, _ := newLeaseApp(t)
	for _, action := range appBoundActions {
		response := app.HandleAppRequest(sessionA, "", []byte(`{"action":"`+action+`","request_id":"x","payload":{}}`))
		if response.ErrorCode == ErrCodeChatAppCallerRequired || response.ErrorCode == ErrCodeChatRuntimeLeaseRequired {
			t.Fatalf("%s from the App was refused at the gate: %+v", action, response)
		}
	}
}
