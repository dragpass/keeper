// ping_test.go — regression guard for ping.go (HandlePing).
//
// **Defects this test catches:**
//   - regressions where the handler calls stdlib `log.*` directly (bypassing a.Logger)
//   - regressions where the response envelope shape seen by the dispatcher breaks
package handlers

import (
	"slices"
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
	// Old and new builds can report the same version string; the contract is
	// what the extension gates chat on.
	if data.ChatContract != 5 {
		t.Fatalf("chat_contract = %d, want 5", data.ChatContract)
	}
	want := []string{"permit.v5", "roles.v1", "statements.v1", "handover.v1", "recovery.v1",
		"pool_sweep.v1", "sync_block.v1", "safety_number.v1", "removed_accounts.v1"}
	if !slices.Equal(data.ChatCapabilities, want) {
		t.Fatalf("chat_capabilities = %v, want %v", data.ChatCapabilities, want)
	}
}
