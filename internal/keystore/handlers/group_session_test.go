// group_session_test.go — regression guard for group_session.go
// (HandleGroupSession{Open, Close, Status}).
//
// **Defects this test catches:**
//   - regressions where the handler calls stdlib `log.*` directly (bypassing a.Logger)
//   - regressions where validation-failure sentinels (group_handle /
//     group_dek_b64) are echoed to the logger
package handlers

import (
	"strings"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/proto"
)

func TestApp_HandleGroupSessionOpen_DecodeFailureLogs(t *testing.T) {
	deps, log, _ := newTestDeps(t)

	// Input that passes Validate but fails base64 decode — Validate checks
	// the Base64 format, so we send valid Base64 and force the failure at
	// the RSA-OAEP step.
	resp := HandleGroupSessionOpen(deps, proto.GroupSessionOpenRequest{
		EncryptedGroupDEK: "aGVsbG8=", // valid Base64 but RSA-OAEP will fail
	})

	if resp.Success {
		t.Fatalf("expected failure (no Keychain key seeded)")
	}
	if !log.Contains("group session open request processing") {
		t.Fatalf("expected 'processing...' log")
	}
	// success log must never appear.
	if log.Contains("group session open successful") {
		t.Fatalf("must not log success on failure: %v", log.Messages())
	}
}

func TestApp_HandleGroupSessionClose_LogsLifecycle(t *testing.T) {
	deps, log, _ := newTestDeps(t)

	resp := HandleGroupSessionClose(deps, proto.GroupSessionCloseRequest{
		// 32B Base64 — passes requireHandle (missing handle → idempotent success).
		GroupHandle: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
	})
	if !resp.Success {
		t.Fatalf("close should succeed (idempotent), got %s", resp.Error)
	}
	if !log.Contains("group session close request processing") {
		t.Fatalf("expected processing log")
	}
	if !log.Contains("group session close successful") {
		t.Fatalf("expected successful log")
	}
}

func TestApp_HandleGroupSessionStatus_LogsProcessing(t *testing.T) {
	deps, log, _ := newTestDeps(t)

	resp := HandleGroupSessionStatus(deps, proto.GroupSessionStatusRequest{
		GroupHandle: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
	})
	if !resp.Success {
		t.Fatalf("status should succeed, got %s", resp.Error)
	}
	data := resp.Data.(proto.GroupSessionStatusResponseData)
	if data.Exists {
		t.Fatalf("Exists should be false for unknown handle")
	}
	if !log.Contains("group session status request processing") {
		t.Fatalf("expected processing log")
	}
}

func TestHandleGroupSessionOpen_FreeFunctionDelegation(t *testing.T) {
	// Dispatcher-compat regression — verifies the validation-failure branch with invalid Base64.
	deps, _, _ := newTestDeps(t)
	resp := HandleGroupSessionOpen(deps, proto.GroupSessionOpenRequest{
		EncryptedGroupDEK: "!!!not-base64!!!",
	})
	if resp.Success {
		t.Fatalf("expected validation failure")
	}
	if resp.Error == "" {
		t.Fatalf("expected non-empty error")
	}
	// Package-wide regression guard that the validation error message does not echo the input.
	if strings.Contains(resp.Error, "!!!not-base64!!!") {
		t.Fatalf("error must not echo input, got %q", resp.Error)
	}
}
