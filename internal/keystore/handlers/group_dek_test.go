// group_dek_test.go — regression guard for group_dek.go (HandleWrapGroupDEK /
// HandleDEKRewrapWithOldKey).
//
// **Defects this test catches:**
//   - regressions where the handler calls stdlib `log.*` directly (bypassing a.Logger)
//   - regressions where verifier-using handlers call free `VerifyServerSig` directly
//   - regressions where secret input values (group_dek_b64) are echoed to the logger
package handlers

import (
	"errors"
	"strings"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/proto"
)

// TestApp_HandleWrapGroupDEK_DoesNotEchoGroupDEK: the raw group_dek_b64
// sentinel must not be echoed to the logger on the decode-failure branch.
// **Core regression guard.**
func TestApp_HandleWrapGroupDEK_DoesNotEchoGroupDEK(t *testing.T) {
	deps, log, _ := newTestDeps(t)

	// invalid Base64 → enters the decode-failure branch
	const groupDEKSentinel = "RAW_GROUP_DEK_SENTINEL_DO_NOT_LEAK_TO_LOGS!!!"
	resp := HandleWrapGroupDEK(deps, proto.WrapGroupDEKRequest{
		GroupDEKB64:        groupDEKSentinel,
		RecipientPublicKey: "-----BEGIN PUBLIC KEY-----\nfake\n-----END PUBLIC KEY-----",
	})
	if resp.Success {
		t.Fatalf("expected failure for invalid Base64")
	}
	if log.Contains(groupDEKSentinel) {
		t.Fatalf("logger leaked group_dek_b64: %v", log.Messages())
	}
}

// TestApp_HandleDEKRewrapWithOldKey_VerifyFailedShortCircuits: must not enter
// the store Use branch when the verifier fails.
func TestApp_HandleDEKRewrapWithOldKey_VerifyFailedShortCircuits(t *testing.T) {
	deps, log, _ := newTestDepsFailVerify(t, errors.New("server signature verification failed: stub"))

	resp := HandleDEKRewrapWithOldKey(deps, proto.DEKRewrapWithOldKeyRequest{
		ChallengeToken:    "any",
		Signature:         "any",
		EncryptedGroupDEK: "AAAA",
		NewPublicKey:      "-----BEGIN PUBLIC KEY-----\nfake\n-----END PUBLIC KEY-----",
		RecoveryHandle:    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", // 32B Base64
	})
	if resp.Success {
		t.Fatalf("expected failure when verifier rejects")
	}
	if !strings.Contains(resp.Error, "server signature verification failed") {
		t.Fatalf("error must include verifier failure prefix, got %q", resp.Error)
	}
	if log.Contains("dek rewrap with old key successful") {
		t.Fatalf("must not log success on verifier failure")
	}
}
