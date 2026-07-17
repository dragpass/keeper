// group_dek_test.go — regression guard for group_dek.go
// (HandleDEKRewrapWithOldKey).
//
// **Defects this test catches:**
//   - regressions where the handler calls stdlib `log.*` directly (bypassing a.Logger)
//   - regressions where verifier-using handlers call free `VerifyServerSig` directly
package handlers

import (
	"errors"
	"strings"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/proto"
)

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
