// group_encrypt_validate_test.go — GroupEncryptRequest.Validate() negative-case
// regression guard. Mirrors aes_actions_validate_test.go.
//
// VALID_HANDLE / SECRET_VALUE are declared in aes_actions_validate_test.go
// (same package).
package proto

import (
	"strings"
	"testing"
)

func TestGroupEncrypt_Validate_RejectsInvalidBase64(t *testing.T) {
	r := GroupEncryptRequest{
		GroupHandle:  VALID_HANDLE,
		PlaintextB64: "!!!not-base64!!!",
	}
	err := r.Validate()
	if err == nil {
		t.Fatalf("expected validation error for invalid Base64")
	}
	if !strings.Contains(err.Error(), "plaintext_b64") {
		t.Fatalf("error must mention field, got %q", err.Error())
	}
}

func TestGroupEncrypt_Validate_RejectsBadHandle(t *testing.T) {
	r := GroupEncryptRequest{
		GroupHandle:  "", // too short / empty
		PlaintextB64: "aGVsbG8=",
	}
	err := r.Validate()
	if err == nil {
		t.Fatalf("expected validation error for empty handle")
	}
	if !strings.Contains(err.Error(), "group_handle") {
		t.Fatalf("error must mention field, got %q", err.Error())
	}
}

func TestGroupEncrypt_Validate_DoesNotEchoSecretInError(t *testing.T) {
	// On validation failure the error message must not echo the input.
	r := GroupEncryptRequest{
		GroupHandle:  "", // forces validation failure before plaintext is checked
		PlaintextB64: SECRET_VALUE,
	}
	err := r.Validate()
	if err == nil {
		t.Fatalf("expected error")
	}
	if strings.Contains(err.Error(), "SUPER_SECRET") {
		t.Fatalf("validation error must not echo input value, got %q", err.Error())
	}
}
