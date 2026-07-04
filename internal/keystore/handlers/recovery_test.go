// recovery_test.go — regression guard for recovery.go (HandleRecoverySign /
// HandleGenerateKeypairWithRecoveryWrap).
//
// **Defects this test catches:**
//   - regressions where the handler calls stdlib `log.*` directly (bypassing a.Logger)
//   - regressions where verifier-using handlers call free `VerifyServerSig` directly
//   - regressions where the wrap_key_b64 secret input is echoed to the logger
package handlers

import (
	"errors"
	"strings"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/proto"
)

// TestApp_HandleRecoverySign_VerifyFailedShortCircuits: must not enter the
// store Use branch when the verifier fails.
func TestApp_HandleRecoverySign_VerifyFailedShortCircuits(t *testing.T) {
	deps, log, _ := newTestDepsFailVerify(t, errors.New("server signature verification failed: stub"))

	resp := HandleRecoverySign(deps, proto.RecoverySignRequest{
		ChallengeToken: "any-challenge",
		Signature:      "any-sig",
		RecoveryHandle: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", // 32B Base64
	})
	if resp.Success {
		t.Fatalf("expected failure when verifier rejects")
	}
	if !strings.Contains(resp.Error, "server signature verification failed") {
		t.Fatalf("error must include verifier failure prefix, got %q", resp.Error)
	}
	if !log.Contains("recovery sign request processing") {
		t.Fatalf("expected processing log")
	}
	if log.Contains("recovery sign successful") {
		t.Fatalf("must not log success on verifier failure")
	}
}

// TestApp_HandleGenerateKeypairWithRecoveryWrap_VerifyFailedShortCircuits:
// must not enter the keypair-generation branch.
func TestApp_HandleGenerateKeypairWithRecoveryWrap_VerifyFailedShortCircuits(t *testing.T) {
	deps, log, _ := newTestDepsFailVerify(t, errors.New("server signature verification failed: stub"))

	resp := HandleGenerateKeypairWithRecoveryWrap(deps, proto.GenerateKeypairWithRecoveryWrapRequest{
		ChallengeToken: "any-challenge",
		Signature:      "any-sig",
		WrapKeyB64:     "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", // 32B Base64
	})
	if resp.Success {
		t.Fatalf("expected failure when verifier rejects")
	}
	if !strings.Contains(resp.Error, "server signature verification failed") {
		t.Fatalf("error must include verifier failure prefix, got %q", resp.Error)
	}
	if log.Contains("recovery keypair generated") {
		t.Fatalf("must not log keypair generation on verifier failure")
	}
}

// TestApp_HandleGenerateKeypairWithRecoveryWrap_DoesNotEchoWrapKey: the
// wrap_key sentinel must not be echoed to the logger.
func TestApp_HandleGenerateKeypairWithRecoveryWrap_DoesNotEchoWrapKey(t *testing.T) {
	deps, log, _ := newTestDepsFailVerify(t, errors.New("server signature verification failed: stub"))

	const wrapKeySentinel = "WRAP_KEY_SENTINEL_DO_NOT_LEAK_INTO_LOGS"
	resp := HandleGenerateKeypairWithRecoveryWrap(deps, proto.GenerateKeypairWithRecoveryWrapRequest{
		ChallengeToken: "any",
		Signature:      "any",
		WrapKeyB64:     wrapKeySentinel,
	})
	if resp.Success {
		t.Fatalf("expected failure")
	}
	if log.Contains(wrapKeySentinel) {
		t.Fatalf("logger leaked wrap_key_b64: %v", log.Messages())
	}
}

// TestHandleRecoverySign_ValidationDelegation: same-envelope-as-dispatcher regression guard.
func TestHandleRecoverySign_ValidationDelegation(t *testing.T) {
	deps, _, _ := newTestDeps(t)
	resp := HandleRecoverySign(deps, proto.RecoverySignRequest{
		ChallengeToken: "",
		Signature:      "",
		RecoveryHandle: "",
	})
	if resp.Success {
		t.Fatalf("expected validation failure")
	}
	if resp.Error == "" {
		t.Fatalf("expected non-empty error")
	}
}
