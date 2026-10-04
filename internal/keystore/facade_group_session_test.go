package keystore

import (
	"fmt"
	"testing"
)

func openTestGroupSession(t *testing.T, app *App, raw []byte) string {
	t.Helper()
	rawCopy := append([]byte(nil), raw...)
	handle, _, err := app.GroupSessions.Open(rawCopy)
	if err != nil {
		t.Fatalf("openTestGroupSession: %v", err)
	}
	t.Cleanup(func() {
		app.GroupSessions.Close(handle)
	})
	return handle
}

func TestHandleRequest_GroupSession_FullLifecycle(t *testing.T) {
	app := newFacadeTestApp()
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(0xa0 + i)
	}
	handle := openTestGroupSession(t, app, raw)

	if exists, remaining := app.GroupSessions.Status(handle); !exists || remaining <= 0 {
		t.Fatalf("open handle: exists=%v remaining_ms=%d", exists, remaining)
	}

	closeMsg := fmt.Sprintf(`{"action":"group_session_close","payload":{"group_handle":%q}}`, handle)
	closeResp := app.HandleRequest([]byte(closeMsg))
	if !closeResp.Success {
		t.Fatalf("close: %s", closeResp.Error)
	}

	if exists, _ := app.GroupSessions.Status(handle); exists {
		t.Error("handle still exists after close")
	}

	closeResp2 := app.HandleRequest([]byte(closeMsg))
	if !closeResp2.Success {
		t.Errorf("idempotent close: %s", closeResp2.Error)
	}
}
