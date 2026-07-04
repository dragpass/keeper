// ping_test.go — regression guard for ping.go (HandlePing).
//
// **Defects this test catches:**
//   - regressions where the handler calls stdlib `log.*` directly (bypassing a.Logger)
//   - regressions where the response envelope shape seen by the dispatcher breaks
package handlers

import (
	"testing"

	"github.com/dragpass/keeper/internal/keystore/proto"
)

func TestApp_HandlePing_LogsProcessing(t *testing.T) {
	deps, log, _ := newTestDeps(t)

	resp := HandlePing(deps, proto.PingRequest{})
	if !resp.Success {
		t.Fatalf("ping should succeed: %s", resp.Error)
	}
	if !log.Contains("ping request processing") {
		t.Fatalf("expected processing log, got %v", log.Messages())
	}
}

// TestHandlePing_BareDelegation: empty deps + ping call returns the same
// response envelope seen by the dispatcher.
func TestHandlePing_BareDelegation(t *testing.T) {
	deps, _, _ := newTestDeps(t)
	resp := HandlePing(deps, proto.PingRequest{})
	if !resp.Success {
		t.Fatalf("ping should succeed: %s", resp.Error)
	}
	data, ok := resp.Data.(proto.PingResponseData)
	if !ok {
		t.Fatalf("expected PingResponseData, got %T", resp.Data)
	}
	if data.Version == "" {
		t.Fatalf("expected non-empty version")
	}
}
