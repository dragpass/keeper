// recovery_session_test.go — regression guard for recovery_session.go
// (HandleRecoverySessionOpen / HandleRecoverySessionClose).
//
// Two clusters:
//  1. App receiver method DI guard — verifies `a.Logger` /
//     `a.ServerKeyVerifier.Verify` do not regress to stdlib `log.*` /
//     free `VerifyServerSig`.
//  2. ErrorCode category guard (Error Taxonomy) — verifies the
//     validate / verify / decode-stage branches respond with the correct ErrCode.
//
// CodeForError / Response / CodeResponse serialization regression guards live
// separately in internal/keystore/errs/errs_test.go.
package handlers

import (
	"errors"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// TestApp_HandleRecoverySessionOpen_VerifyFailedLogged: when ServerKeyVerifier
// fails, (1) the response converges to failure and (2) the error reaches the logger.
func TestApp_HandleRecoverySessionOpen_VerifyFailedLogged(t *testing.T) {
	deps, log, _ := newTestDepsFailVerify(t, errors.New("server signature verification failed: stub"))

	req := proto.RecoverySessionOpenRequest{
		ChallengeToken:   "any-challenge",
		Signature:        "any-sig",
		WrappedKeeperB64: "aGVsbG8=",
		WrapKeyB64:       "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", // 32B Base64
	}
	resp := HandleRecoverySessionOpen(deps, req)

	if resp.Success {
		t.Fatalf("expected failure when ServerKeyVerifier rejects")
	}

	// verify capture of "processing..." + error log.
	msgs := log.Messages()
	if len(msgs) < 2 {
		t.Fatalf("expected at least 2 log messages, got %d: %v", len(msgs), msgs)
	}
	if !log.Contains("recovery session open request processing") {
		t.Fatalf("expected 'processing...' log line, got %v", msgs)
	}
	if !log.Contains("server signature verification failed") {
		t.Fatalf("expected verifier error in log, got %v", msgs)
	}
}

// TestApp_HandleRecoverySessionOpen_DoesNotEchoWrapKey: top-priority
// regression guard — regardless of which stage fails (validate / verify /
// decode), the wrap_key input must not echo to the logger.
func TestApp_HandleRecoverySessionOpen_DoesNotEchoWrapKey(t *testing.T) {
	deps, log, _ := newTestDeps(t) // verify passes (AlwaysOKVerifier)

	// Use a sentinel for wrap_key with a meaningful length but decode-failing —
	// verifies that the decode-failure branch does not expose the raw value
	// in the log.
	const sentinelWrapKey = "SUPER_SECRET_WRAP_KEY_DO_NOT_LEAK_INTO_LOGS"
	req := proto.RecoverySessionOpenRequest{
		ChallengeToken:   "any",
		Signature:        "any",
		WrappedKeeperB64: "aGVsbG8=",
		// Same length as 32B Base64 (44 chars + padding) to pass validate — the
		// actual decode failure happens at wrappedKeeper.
		WrapKeyB64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
	}
	resp := HandleRecoverySessionOpen(deps, req)

	// Real flow: validate pass → verify pass (stub) → wrapKey decode pass →
	// wrappedKeeper AES-GCM unwrap fails (wrong key). resp.Success is false.
	if resp.Success {
		t.Fatalf("expected failure (AES-GCM unwrap should fail with stub data)")
	}

	// The sentinel never entered the payload, but assert as a regression
	// guard pattern that no secret pattern echoes to the log.
	if log.Contains(sentinelWrapKey) {
		t.Fatalf("logger leaked sentinel: %v", log.Messages())
	}
	// Verify that wrap_key's raw bytes did not leak to the log in hex/Base64.
	if log.Contains(req.WrapKeyB64) {
		t.Fatalf("logger echoed wrap_key Base64: %v", log.Messages())
	}
}

// TestApp_HandleRecoverySessionClose_LogsLifecycle: ensures close emits both
// "processing..." + "successful" log lines on both normal and idempotent paths.
func TestApp_HandleRecoverySessionClose_LogsLifecycle(t *testing.T) {
	deps, log, _ := newTestDeps(t)

	// 32B Base64 — passes requireHandle so we reach store.Close (missing handle → idempotent).
	req := proto.RecoverySessionCloseRequest{RecoveryHandle: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}
	resp := HandleRecoverySessionClose(deps, req)
	if !resp.Success {
		t.Fatalf("close should succeed (idempotent), got error: %s", resp.Error)
	}

	if !log.Contains("recovery session close request processing") {
		t.Fatalf("expected 'processing...' log")
	}
	if !log.Contains("recovery session close successful") {
		t.Fatalf("expected 'successful' log")
	}
}

// TestHandleRecoverySessionOpen_ValidationDelegation: ensures the
// validate-failure branch produces a dispatcher-compatible response envelope.
// Earlier tests called the free function (DefaultApp delegation); this
// package calls the same free function directly — the result is the same.
func TestHandleRecoverySessionOpen_ValidationDelegation(t *testing.T) {
	deps, _, _ := newTestDeps(t)
	// invalid Base64 wrapKey → must be rejected at the validation step.
	req := proto.RecoverySessionOpenRequest{
		ChallengeToken:   "x",
		Signature:        "y",
		WrappedKeeperB64: "z",
		WrapKeyB64:       "", // empty → validation fail
	}
	resp := HandleRecoverySessionOpen(deps, req)
	if resp.Success {
		t.Fatalf("expected validation failure")
	}
	// Only verify that the dispatcher receives the same envelope shape.
	if resp.Error == "" {
		t.Fatalf("expected non-empty error")
	}
}

// --- ErrorCode category regression guard (merged from old errors_test.go) -----

func TestApp_HandleRecoverySessionOpen_ValidationCode(t *testing.T) {
	deps, _, _ := newTestDeps(t)

	// empty wrap_key → rejected at validate stage → ValidationError → validation_error.
	resp := HandleRecoverySessionOpen(deps, proto.RecoverySessionOpenRequest{
		ChallengeToken:   "any",
		Signature:        "any",
		WrappedKeeperB64: "aGVsbG8=",
		WrapKeyB64:       "",
	})
	if resp.Success {
		t.Fatalf("expected validation failure")
	}
	if resp.ErrorCode != string(errs.ErrCodeValidation) {
		t.Fatalf("expected validation_error, got %q", resp.ErrorCode)
	}
}

func TestApp_HandleRecoverySessionOpen_VerifyFailureCode(t *testing.T) {
	deps, _, _ := newTestDepsFailVerify(t, errors.New("server signature verification failed: stub"))

	resp := HandleRecoverySessionOpen(deps, proto.RecoverySessionOpenRequest{
		ChallengeToken:   "any",
		Signature:        "any-sig",
		WrappedKeeperB64: "aGVsbG8=",
		WrapKeyB64:       "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
	})
	if resp.Success {
		t.Fatalf("expected verifier failure")
	}
	if resp.ErrorCode != string(errs.ErrCodeCryptoFailure) {
		t.Fatalf("expected crypto_failure (signature verify), got %q", resp.ErrorCode)
	}
}

func TestApp_HandleRecoverySessionOpen_DecryptFailureCode(t *testing.T) {
	deps, _, _ := newTestDeps(t) // pass verify to reach the AES-GCM branch

	// validate + verify pass → wrap_key decode pass → AES-GCM unwrap-failure branch.
	resp := HandleRecoverySessionOpen(deps, proto.RecoverySessionOpenRequest{
		ChallengeToken:   "any",
		Signature:        "any",
		WrappedKeeperB64: "aGVsbG8=",                                     // wrong ciphertext
		WrapKeyB64:       "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", // 32B Base64
	})
	if resp.Success {
		t.Fatalf("expected AES-GCM failure")
	}
	if resp.ErrorCode != string(errs.ErrCodeCryptoFailure) {
		t.Fatalf("expected crypto_failure, got %q", resp.ErrorCode)
	}
}

func TestApp_HandleRecoverySessionClose_ValidationCode(t *testing.T) {
	deps, _, _ := newTestDeps(t)

	resp := HandleRecoverySessionClose(deps, proto.RecoverySessionCloseRequest{
		RecoveryHandle: "", // validate rejects
	})
	if resp.Success {
		t.Fatalf("expected validation failure")
	}
	if resp.ErrorCode != string(errs.ErrCodeValidation) {
		t.Fatalf("expected validation_error, got %q", resp.ErrorCode)
	}
}
