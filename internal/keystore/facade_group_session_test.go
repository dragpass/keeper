package keystore

import (
	"encoding/json"
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

	statusMsg := fmt.Sprintf(`{"action":"group_session_status","payload":{"group_handle":%q}}`, handle)
	statusResp := app.HandleRequest([]byte(statusMsg))
	if !statusResp.Success {
		t.Fatalf("status: %s", statusResp.Error)
	}
	rawStatus, _ := json.Marshal(statusResp.Data)
	var statusData GroupSessionStatusResponseData
	json.Unmarshal(rawStatus, &statusData)
	if !statusData.Exists {
		t.Error("status should report exists=true")
	}
	if statusData.RemainingMs <= 0 {
		t.Errorf("remaining_ms should be > 0, got %d", statusData.RemainingMs)
	}

	closeMsg := fmt.Sprintf(`{"action":"group_session_close","payload":{"group_handle":%q}}`, handle)
	closeResp := app.HandleRequest([]byte(closeMsg))
	if !closeResp.Success {
		t.Fatalf("close: %s", closeResp.Error)
	}

	statusResp2 := app.HandleRequest([]byte(statusMsg))
	if !statusResp2.Success {
		t.Fatalf("status after close: %s", statusResp2.Error)
	}
	rawStatus2, _ := json.Marshal(statusResp2.Data)
	var statusData2 GroupSessionStatusResponseData
	json.Unmarshal(rawStatus2, &statusData2)
	if statusData2.Exists {
		t.Error("status after close should report exists=false")
	}

	closeResp2 := app.HandleRequest([]byte(closeMsg))
	if !closeResp2.Success {
		t.Errorf("idempotent close: %s", closeResp2.Error)
	}
}
