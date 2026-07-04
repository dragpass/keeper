// rotate_keypair_status_abort_test.go — HandleRotateUserKeypairStatus /
// HandleRotateUserKeypairAbort 가드 + 양 핸들러 lifecycle 로그 검증.
package handlers

import (
	"testing"

	"github.com/zalando/go-keyring"

	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

func TestApp_HandleRotateUserKeypairStatus_LogsProcessing(t *testing.T) {
	keyring.MockInit() // empty keychain — all slots empty
	deps, log, _ := newTestDeps(t)

	resp := HandleRotateUserKeypairStatus(deps, proto.RotateUserKeypairStatusRequest{})
	if !resp.Success {
		t.Fatalf("status should succeed on empty keychain, got %s", resp.Error)
	}
	data := resp.Data.(proto.RotateUserKeypairStatusResponseData)
	if data.HasPending {
		t.Fatalf("HasPending must be false on empty keychain")
	}

	if !log.Contains("rotate user keypair status request processing") {
		t.Fatalf("expected processing log")
	}
}

func TestApp_HandleRotateUserKeypairAbort_LogsLifecycle(t *testing.T) {
	keyring.MockInit() // empty keychain
	deps, log, _ := newTestDeps(t)

	// abort from empty state — no-op branch.
	resp := HandleRotateUserKeypairAbort(deps, proto.RotateUserKeypairAbortRequest{})
	if !resp.Success {
		t.Fatalf("abort should succeed (idempotent), got %s", resp.Error)
	}
	data := resp.Data.(proto.RotateUserKeypairAbortResponseData)
	if data.Aborted {
		t.Fatalf("Aborted must be false when nothing to clear")
	}

	if !log.Contains("no pending slot to clear (no-op)") {
		t.Fatalf("expected no-op log on empty keychain, got: %v", log.Messages())
	}
}

func TestHandleRotateUserKeypairStatus_NoPending(t *testing.T) {
	deps, _, store := newTestDeps(t)
	oldPub, _ := seedActiveKeypairForRotateTest(t, store)
	// clean pending slot (helper already does this, but be explicit)
	_ = keychain.DeletePendingPrivateKey(store)
	_ = keychain.DeletePendingPublicKey(store)

	resp := HandleRotateUserKeypairStatus(deps, proto.RotateUserKeypairStatusRequest{})
	if !resp.Success {
		t.Fatalf("status failed: %s", resp.Error)
	}
	data := resp.Data.(proto.RotateUserKeypairStatusResponseData)
	if data.HasPending {
		t.Errorf("expected has_pending=false, got true")
	}
	if data.PendingPublicKey != "" {
		t.Errorf("expected empty pending_public_key, got %q", data.PendingPublicKey)
	}
	if data.ActivePublicKey != oldPub {
		t.Errorf("active_public_key mismatch: got %q want %q", data.ActivePublicKey, oldPub)
	}
}

func TestHandleRotateUserKeypairStatus_HasPending(t *testing.T) {
	deps, _, store := newTestDeps(t)
	oldPub, _ := seedActiveKeypairForRotateTest(t, store)

	prep := HandleRotateUserKeypairPrepare(deps, proto.RotateUserKeypairPrepareRequest{
		ChallengeToken:  "rotate-status-001",
		ServerSignature: "any",
	})
	if !prep.Success {
		t.Fatalf("prepare: %s", prep.Error)
	}
	prepData := prep.Data.(proto.RotateUserKeypairPrepareResponseData)

	resp := HandleRotateUserKeypairStatus(deps, proto.RotateUserKeypairStatusRequest{})
	if !resp.Success {
		t.Fatalf("status failed: %s", resp.Error)
	}
	data := resp.Data.(proto.RotateUserKeypairStatusResponseData)
	if !data.HasPending {
		t.Errorf("expected has_pending=true, got false")
	}
	if data.PendingPublicKey != prepData.NewPublicKey {
		t.Errorf("pending_public_key mismatch: got %q want %q",
			data.PendingPublicKey, prepData.NewPublicKey)
	}
	if data.ActivePublicKey != oldPub {
		t.Errorf("active_public_key mismatch: got %q want %q", data.ActivePublicKey, oldPub)
	}
}

func TestHandleRotateUserKeypairAbort_WithPending(t *testing.T) {
	deps, _, store := newTestDeps(t)
	seedActiveKeypairForRotateTest(t, store)

	prep := HandleRotateUserKeypairPrepare(deps, proto.RotateUserKeypairPrepareRequest{
		ChallengeToken:  "rotate-abort-001",
		ServerSignature: "any",
	})
	if !prep.Success {
		t.Fatalf("prepare: %s", prep.Error)
	}

	// call abort
	abortResp := HandleRotateUserKeypairAbort(deps, proto.RotateUserKeypairAbortRequest{})
	if !abortResp.Success {
		t.Fatalf("abort failed: %s", abortResp.Error)
	}
	data := abortResp.Data.(proto.RotateUserKeypairAbortResponseData)
	if !data.Aborted {
		t.Errorf("expected aborted=true after pending was present")
	}

	// status again: has_pending=false
	statusResp := HandleRotateUserKeypairStatus(deps, proto.RotateUserKeypairStatusRequest{})
	statusData := statusResp.Data.(proto.RotateUserKeypairStatusResponseData)
	if statusData.HasPending {
		t.Errorf("pending still present after abort")
	}
}

func TestHandleRotateUserKeypairAbort_Idempotent(t *testing.T) {
	deps, _, store := newTestDeps(t)
	seedActiveKeypairForRotateTest(t, store)
	_ = keychain.DeletePendingPrivateKey(store)
	_ = keychain.DeletePendingPublicKey(store)

	abortResp := HandleRotateUserKeypairAbort(deps, proto.RotateUserKeypairAbortRequest{})
	if !abortResp.Success {
		t.Fatalf("abort failed (idempotent path): %s", abortResp.Error)
	}
	data := abortResp.Data.(proto.RotateUserKeypairAbortResponseData)
	if data.Aborted {
		t.Errorf("expected aborted=false when no pending was present")
	}

	// second call is also safe
	abortResp2 := HandleRotateUserKeypairAbort(deps, proto.RotateUserKeypairAbortRequest{})
	if !abortResp2.Success {
		t.Fatalf("second abort failed: %s", abortResp2.Error)
	}
}
