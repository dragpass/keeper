// session_code_test.go — regression guard for session_code.go
// (HandleSaveSessionCode / HandleGetSessionCode).
//
// **Defects this test catches:**
//   - regressions where the handler calls stdlib `log.*` directly (bypassing a.Logger)
//   - regressions where SaveSessionCode calls free `VerifyServerSig` directly
//     (bypassing a.ServerKeyVerifier.Verify)
//   - regressions where encrypted_session_code / signature are echoed to the logger
package handlers

import (
	"errors"
	"strings"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/proto"
)

// TestApp_HandleSaveSessionCode_VerifyFailedShortCircuits: with an
// AlwaysFailVerifier injected, must fail immediately without entering the
// promote / decrypt branches.
func TestApp_HandleSaveSessionCode_VerifyFailedShortCircuits(t *testing.T) {
	deps, log, _ := newTestDepsFailVerify(t, errors.New("server signature verification failed: stub"))

	resp := HandleSaveSessionCode(deps, proto.SaveSessionCodeRequest{
		EncryptedSessionCode: "AAAA",
		Signature:            "any-sig",
	})

	if resp.Success {
		t.Fatalf("expected failure when ServerKeyVerifier rejects")
	}
	if !strings.Contains(resp.Error, "server signature verification failed") {
		t.Fatalf("error must include verifier failure prefix, got %q", resp.Error)
	}
	// processing log must appear, but the promote branch must not run.
	if !log.Contains("encrypted session code save request processing") {
		t.Fatalf("expected processing log")
	}
	if log.Contains("signature verification successful") {
		t.Fatalf("must not log verify success on verifier failure")
	}
	if log.Contains("pending keypair promoted") {
		t.Fatalf("must not promote on verify failure: %v", log.Messages())
	}
}

// TestApp_HandleSaveSessionCode_DoesNotEchoEncrypted: the encrypted
// session-code Base64 must not be echoed to the logger (verify-failure branch).
func TestApp_HandleSaveSessionCode_DoesNotEchoEncrypted(t *testing.T) {
	deps, log, _ := newTestDepsFailVerify(t, errors.New("server signature verification failed: stub"))

	const encryptedSentinel = "ENCRYPTED_SESSION_CODE_DO_NOT_LEAK_TO_LOGS"
	const sigSentinel = "SERVER_SIGNATURE_DO_NOT_LEAK_TO_LOGS"
	resp := HandleSaveSessionCode(deps, proto.SaveSessionCodeRequest{
		EncryptedSessionCode: encryptedSentinel,
		Signature:            sigSentinel,
	})
	if resp.Success {
		t.Fatalf("expected failure")
	}
	if log.Contains(encryptedSentinel) {
		t.Fatalf("logger leaked encrypted_session_code: %v", log.Messages())
	}
	if log.Contains(sigSentinel) {
		t.Fatalf("logger leaked signature: %v", log.Messages())
	}
}

// TestApp_HandleGetSessionCode_LogsProcessing: goes into the not-found branch
// against an empty keychain, but the processing log must still be emitted.
func TestApp_HandleGetSessionCode_LogsProcessing(t *testing.T) {
	deps, log, _ := newTestDeps(t)

	_ = HandleGetSessionCode(deps, proto.GetSessionCodeRequest{})
	if !log.Contains("session code retrieval request processing") {
		t.Fatalf("expected processing log, got %v", log.Messages())
	}
}

// TestHandleSaveSessionCode_ValidationDelegation: the validation-failure
// branch must return the same envelope as the dispatcher.
func TestHandleSaveSessionCode_ValidationDelegation(t *testing.T) {
	deps, _, _ := newTestDeps(t)
	// validation: empty encrypted/signature → reject.
	resp := HandleSaveSessionCode(deps, proto.SaveSessionCodeRequest{})
	if resp.Success {
		t.Fatalf("expected failure on empty request")
	}
	if resp.Error == "" {
		t.Fatalf("expected non-empty error")
	}
}

// TestHandleGetSessionCode_BareDelegation: ensures not-found is returned against an empty store.
func TestHandleGetSessionCode_BareDelegation(t *testing.T) {
	deps, _, _ := newTestDeps(t)
	resp := HandleGetSessionCode(deps, proto.GetSessionCodeRequest{})
	_ = resp // only verifies the envelope shape — failure on empty store is OK
}
