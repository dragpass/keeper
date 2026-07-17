// Non-AES Request Validate() — regression guard for handlers migrated to
// validation helpers (keeper-lgpl-p0 follow-up).
//
// **What this catches:**
//   - Empty-string reject regressions after migrating to validation
//     helpers.
//   - Base64Len(32) / Base64Len(12) / handle / PEM reinforcement points
//     being defanged.
//   - Input payload (DEK / PEM / IV / ciphertext) being echoed in error
//     messages.
package proto

import (
	"strings"
	"testing"
)

const (
	testValidHandle = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" // 32B Base64
	testValid32BKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" // 32B = AES-256 / Group DEK
	testValid12BIV  = "AAAAAAAAAAAAAAAA"                             // 12B = AES-GCM IV
	testValidBase64 = "aGVsbG8="                                     // "hello"
	testValidPubPEM = "-----BEGIN PUBLIC KEY-----\nABC\n-----END PUBLIC KEY-----"
	testSecretLeak  = "SUPER_SECRET_DO_NOT_LEAK_BASE64_PAYLOAD=="
	testInvalidB64  = "!!!not-base64!!!"
	testInvalidPEM  = "not-a-pem-string"
	testShortHandle = "tooshort"
)

// ────────────────────────────────────────────────────────────────────────
// Identity / Signup / Login
// ────────────────────────────────────────────────────────────────────────

func TestSaveDeviceKey_Validate_RejectsNon32BLength(t *testing.T) {
	// Only 16B in the Base64 — requireBase64Len(32) rejects.
	r := SaveDeviceKeyRequest{Key: "AAAAAAAAAAAAAAAAAAAAAg=="}
	err := r.Validate()
	if err == nil {
		t.Fatalf("expected error for non-32B device key")
	}
	if !strings.Contains(err.Error(), "key") {
		t.Fatalf("error must mention field, got %q", err.Error())
	}
}

func TestSaveDeviceKey_Validate_AcceptsValid32B(t *testing.T) {
	r := SaveDeviceKeyRequest{Key: testValid32BKey}
	if err := r.Validate(); err != nil {
		t.Fatalf("valid 32B key rejected: %v", err)
	}
}

func TestSaveSessionCode_Validate_RejectsInvalidBase64(t *testing.T) {
	r := SaveSessionCodeRequest{
		EncryptedSessionCode: testInvalidB64,
		Signature:            "sig",
	}
	if err := r.Validate(); err == nil {
		t.Fatalf("expected error for invalid Base64")
	}
}

// ────────────────────────────────────────────────────────────────────────
// Recovery family
// ────────────────────────────────────────────────────────────────────────

func TestRecoverySign_Validate_RejectsShortHandle(t *testing.T) {
	r := RecoverySignRequest{
		ChallengeToken: "ct",
		Signature:      "sig",
		RecoveryHandle: testShortHandle,
	}
	if err := r.Validate(); err == nil {
		t.Fatalf("expected error for short handle")
	}
}

func TestGenerateKeypairWithRecoveryWrap_Validate_RejectsNon32BWrapKey(t *testing.T) {
	r := GenerateKeypairWithRecoveryWrapRequest{
		ChallengeToken: "ct",
		Signature:      "sig",
		WrapKeyB64:     "AAAAAAAAAAAAAAAAAAAAAg==", // 16B
	}
	err := r.Validate()
	if err == nil {
		t.Fatalf("expected error for non-32B wrap_key")
	}
	if !strings.Contains(err.Error(), "wrap_key_b64") {
		t.Fatalf("error must mention field, got %q", err.Error())
	}
}

func TestRecoverySessionOpen_Validate_RejectsInvalidWrappedKeeper(t *testing.T) {
	r := RecoverySessionOpenRequest{
		ChallengeToken:   "ct",
		Signature:        "sig",
		WrappedKeeperB64: testInvalidB64,
		WrapKeyB64:       testValid32BKey,
	}
	if err := r.Validate(); err == nil {
		t.Fatalf("expected error for invalid wrapped_keeper Base64")
	}
}

func TestRecoverySessionClose_Validate_RejectsShortHandle(t *testing.T) {
	r := RecoverySessionCloseRequest{RecoveryHandle: testShortHandle}
	if err := r.Validate(); err == nil {
		t.Fatalf("expected error for short handle")
	}
}

// ────────────────────────────────────────────────────────────────────────
// Group DEK wrap/unwrap
// ────────────────────────────────────────────────────────────────────────

func TestWrapGroupDEK_Validate_RejectsNon32BGroupDEK(t *testing.T) {
	r := WrapGroupDEKRequest{
		GroupDEKB64:        "AAAAAAAAAAAAAAAAAAAAAg==", // 16B
		RecipientPublicKey: testValidPubPEM,
	}
	err := r.Validate()
	if err == nil {
		t.Fatalf("expected error for non-32B group_dek")
	}
	if !strings.Contains(err.Error(), "group_dek_b64") {
		t.Fatalf("error must mention field, got %q", err.Error())
	}
}

func TestWrapGroupDEK_Validate_RejectsNonPEMRecipient(t *testing.T) {
	r := WrapGroupDEKRequest{
		GroupDEKB64:        testValid32BKey,
		RecipientPublicKey: testInvalidPEM,
	}
	err := r.Validate()
	if err == nil {
		t.Fatalf("expected error for non-PEM recipient_public_key")
	}
	if !strings.Contains(err.Error(), "recipient_public_key") {
		t.Fatalf("error must mention field, got %q", err.Error())
	}
}

func TestDEKRewrapWithOldKey_Validate_RejectsShortHandle(t *testing.T) {
	r := DEKRewrapWithOldKeyRequest{
		ChallengeToken:    "ct",
		Signature:         "sig",
		RecoveryHandle:    testShortHandle,
		EncryptedGroupDEK: testValidBase64,
		NewPublicKey:      testValidPubPEM,
	}
	if err := r.Validate(); err == nil {
		t.Fatalf("expected error for short handle")
	}
}

func TestDEKRewrapWithOldKey_Validate_RejectsNonPEMNewKey(t *testing.T) {
	r := DEKRewrapWithOldKeyRequest{
		ChallengeToken:    "ct",
		Signature:         "sig",
		RecoveryHandle:    testValidHandle,
		EncryptedGroupDEK: testValidBase64,
		NewPublicKey:      testInvalidPEM,
	}
	err := r.Validate()
	if err == nil {
		t.Fatalf("expected error for non-PEM new_public_key")
	}
	if !strings.Contains(err.Error(), "new_public_key") {
		t.Fatalf("error must mention field, got %q", err.Error())
	}
}

// ────────────────────────────────────────────────────────────────────────
// Group session
// ────────────────────────────────────────────────────────────────────────

func TestGroupSessionOpen_Validate_RejectsInvalidBase64(t *testing.T) {
	r := GroupSessionOpenRequest{EncryptedGroupDEK: testInvalidB64}
	if err := r.Validate(); err == nil {
		t.Fatalf("expected error for invalid Base64")
	}
}

func TestGroupSessionClose_Validate_RejectsShortHandle(t *testing.T) {
	r := GroupSessionCloseRequest{GroupHandle: testShortHandle}
	if err := r.Validate(); err == nil {
		t.Fatalf("expected error for short handle")
	}
}

func TestGroupSessionStatus_Validate_RejectsShortHandle(t *testing.T) {
	r := GroupSessionStatusRequest{GroupHandle: testShortHandle}
	if err := r.Validate(); err == nil {
		t.Fatalf("expected error for short handle")
	}
}

// ────────────────────────────────────────────────────────────────────────
// Personal DEK
// ────────────────────────────────────────────────────────────────────────

func TestDEKRotateToDeviceKey_Validate_RejectsInvalidBase64(t *testing.T) {
	r := DEKRotateToDeviceKeyRequest{
		Password:        "pw",
		EncryptedDEKB64: testInvalidB64,
	}
	if err := r.Validate(); err == nil {
		t.Fatalf("expected error for invalid Base64 encrypted_dek")
	}
}

func TestDEKUnwrapAndEncrypt_Validate_RejectsInvalidBase64(t *testing.T) {
	r := DEKUnwrapAndEncryptRequest{
		EncryptedDEKB64: testInvalidB64,
		PlaintextB64:    testValidBase64,
	}
	if err := r.Validate(); err == nil {
		t.Fatalf("expected error for invalid Base64")
	}
}

// TestDEKUnwrapAndDecrypt_Validate_* was removed alongside the
// DEKUnwrapAndDecryptRequest type. 12B IV / shape checks are covered by the
// DEKUnwrapAndDecryptToClipboardRequest unit tests via the same helper
// (requireBase64Len).

// ────────────────────────────────────────────────────────────────────────
// Admin synthetic (Group DEK generate-and-open / rewrap-for-member)
// ────────────────────────────────────────────────────────────────────────

func TestGroupDEKGenerateAndOpen_Validate_RejectsNonPEM(t *testing.T) {
	r := GroupDEKGenerateAndOpenRequest{MyPublicKey: testInvalidPEM}
	err := r.Validate()
	if err == nil {
		t.Fatalf("expected error for non-PEM my_public_key")
	}
	if !strings.Contains(err.Error(), "my_public_key") {
		t.Fatalf("error must mention field, got %q", err.Error())
	}
}

func TestDEKRewrapForMember_Validate_RejectsInvalidBase64(t *testing.T) {
	r := DEKRewrapForMemberRequest{
		WrappedForMeB64: testInvalidB64,
		OtherPublicKey:  testValidPubPEM,
	}
	if err := r.Validate(); err == nil {
		t.Fatalf("expected error for invalid Base64")
	}
}

func TestDEKRewrapForMember_Validate_RejectsNonPEM(t *testing.T) {
	r := DEKRewrapForMemberRequest{
		WrappedForMeB64: testValidBase64,
		OtherPublicKey:  testInvalidPEM,
	}
	err := r.Validate()
	if err == nil {
		t.Fatalf("expected error for non-PEM other_public_key")
	}
	if !strings.Contains(err.Error(), "other_public_key") {
		t.Fatalf("error must mention field, got %q", err.Error())
	}
}

// ────────────────────────────────────────────────────────────────────────
// Regression guard: validation errors must not echo input payloads
// ────────────────────────────────────────────────────────────────────────

func TestNonAESValidate_DoesNotEchoSecretInError(t *testing.T) {
	cases := []struct {
		name string
		err  error
	}{
		{
			name: "WrapGroupDEK group_dek leaks via wrong length",
			err: (&WrapGroupDEKRequest{
				GroupDEKB64:        testSecretLeak,
				RecipientPublicKey: testValidPubPEM,
			}).Validate(),
		},
		{
			name: "RecoverySessionOpen wrap_key leaks via wrong length",
			err: (&RecoverySessionOpenRequest{
				ChallengeToken:   "ct",
				Signature:        "sig",
				WrappedKeeperB64: testValidBase64,
				WrapKeyB64:       testSecretLeak,
			}).Validate(),
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.err == nil {
				t.Fatalf("expected error")
			}
			if strings.Contains(c.err.Error(), "SUPER_SECRET") {
				t.Fatalf("validation error must not echo input value, got %q", c.err.Error())
			}
		})
	}
}
