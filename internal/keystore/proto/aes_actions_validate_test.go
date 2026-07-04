// AES family Request Validate() — negative-case regression guard.
//
// **What this catches:**
//   - Regression to existing behavior (empty-string reject) when
//     migrating to validation helpers.
//   - Reinforced checks like Base64 / handle / IV length being
//     defanged.
//   - Input payload (WrappedItemDEK, ciphertext) being echoed in error
//     messages.
package proto

import (
	"strings"
	"testing"
)

func TestAESGenerateAndWrap_Validate_RejectsEmptyHandle(t *testing.T) {
	r := AESGenerateAndWrapRequest{GroupHandle: ""}
	err := r.Validate()
	if err == nil {
		t.Fatalf("expected validation error for empty group_handle")
	}
	if !strings.Contains(err.Error(), "group_handle") {
		t.Fatalf("error must mention field name, got %q", err.Error())
	}
}

func TestAESGenerateAndWrap_Validate_RejectsTooShortHandle(t *testing.T) {
	r := AESGenerateAndWrapRequest{GroupHandle: "short"}
	if err := r.Validate(); err == nil {
		t.Fatalf("expected error for handle shorter than minimum length")
	}
}

const VALID_HANDLE = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
const SECRET_VALUE = "SUPER_SECRET_PAYLOAD_DO_NOT_LEAK_BASE64=="

func TestAESUnwrapAndEncrypt_Validate_RejectsInvalidBase64(t *testing.T) {
	r := AESUnwrapAndEncryptRequest{
		WrappedItemDEK: "!!!not-base64!!!",
		GroupHandle:    VALID_HANDLE,
		PlaintextB64:   "aGVsbG8=",
	}
	err := r.Validate()
	if err == nil {
		t.Fatalf("expected validation error for invalid Base64")
	}
	if !strings.Contains(err.Error(), "wrapped_item_dek") {
		t.Fatalf("error must mention field, got %q", err.Error())
	}
}

func TestAESUnwrapAndEncrypt_Validate_DoesNotEchoSecretInError(t *testing.T) {
	// Regression guard: on validation failure, the error message must
	// not echo the input.
	r := AESUnwrapAndEncryptRequest{
		WrappedItemDEK: SECRET_VALUE,
		GroupHandle:    "", // forces validation failure
		PlaintextB64:   "aGVsbG8=",
	}
	err := r.Validate()
	if err == nil {
		t.Fatalf("expected error")
	}
	if strings.Contains(err.Error(), "SUPER_SECRET") {
		t.Fatalf("validation error must not echo input value, got %q", err.Error())
	}
}

// The TestAESUnwrapAndDecrypt_Validate_* series was removed alongside the
// AESUnwrapAndDecryptRequest type. 12B IV / shape checks are covered by the
// AESUnwrapAndDecryptToClipboardRequest unit tests via the same helper
// (requireBase64Len).

// TestAESRewrap_Validate_* series was removed alongside AESRewrapRequest when
// the item_dek_grants schema was dropped (cross-group Item DEK rewrap no
// longer supported).
