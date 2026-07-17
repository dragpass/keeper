// group_dek_test.go — regression guard for group_dek.go (HandleWrapGroupDEK /
// HandleUnwrapGroupDEK / HandleDEKRewrapWithOldKey).
//
// **Defects this test catches:**
//   - regressions where the handler calls stdlib `log.*` directly (bypassing a.Logger)
//   - regressions where verifier-using handlers call free `VerifyServerSig` directly
//   - regressions where secret input values (group_dek_b64) are echoed to the logger
package handlers

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/crypto"
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

// TestApp_HandleUnwrapGroupDEK_LogsProcessing: empty store → private-key
// not-found branch. processing log must appear, success log must not.
func TestApp_HandleUnwrapGroupDEK_LogsProcessing(t *testing.T) {
	deps, log, _ := newTestDeps(t)

	resp := HandleUnwrapGroupDEK(deps, proto.UnwrapGroupDEKRequest{
		EncryptedGroupDEK: "AAAA",
	})
	if resp.Success {
		t.Fatalf("expected failure on empty store")
	}
	if !log.Contains("unwrap group dek request processing") {
		t.Fatalf("expected processing log")
	}
	if log.Contains("unwrap group dek successful") {
		t.Fatalf("must not log success on missing key")
	}
}

// TestApp_HandleUnwrapGroupDEK_SuccessDoesNotEchoRawDEK broadens the
// log-sanitization guard to the raw-return carve-out action: on the success
// path HandleUnwrapGroupDEK returns the raw Group DEK, so the raw bytes must
// never be echoed to the logger.
func TestApp_HandleUnwrapGroupDEK_SuccessDoesNotEchoRawDEK(t *testing.T) {
	deps, log, store := newTestDeps(t)
	pubPEM, _ := setupHandlerKeyPair(t, store)

	// wrap a known raw Group DEK to the stored public key
	groupDEK := make([]byte, 32)
	for i := range groupDEK {
		groupDEK[i] = byte(0xC0 + i)
	}
	pub, err := crypto.ParsePublicKey(pubPEM)
	if err != nil {
		t.Fatalf("ParsePublicKey: %v", err)
	}
	encrypted, err := crypto.EncryptData(pub, groupDEK)
	if err != nil {
		t.Fatalf("EncryptData: %v", err)
	}

	resp := HandleUnwrapGroupDEK(deps, proto.UnwrapGroupDEKRequest{
		EncryptedGroupDEK: base64.StdEncoding.EncodeToString(encrypted),
	})
	if !resp.Success {
		t.Fatalf("unwrap failed: %s", resp.Error)
	}

	// sanity: the returned raw matches the input
	data, ok := resp.Data.(proto.UnwrapGroupDEKResponseData)
	if !ok {
		t.Fatalf("unexpected data type %T", resp.Data)
	}
	rawB64 := base64.StdEncoding.EncodeToString(groupDEK)
	if data.GroupDEKB64 != rawB64 {
		t.Fatal("returned Group DEK does not match input")
	}

	// core guard: the raw Group DEK Base64 must not appear in any log line
	if log.Contains(rawB64) {
		t.Fatalf("logger leaked raw Group DEK: %v", log.Messages())
	}
	if !log.Contains("unwrap group dek successful") {
		t.Fatalf("expected success log")
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
