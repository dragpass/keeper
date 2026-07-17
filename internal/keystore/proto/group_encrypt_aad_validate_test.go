// group_encrypt_aad_validate_test.go — GroupEncryptWithAADRequest.Validate()
// negative-case regression guard. Mirrors group_encrypt_validate_test.go, plus
// the AAD-required case that is the reason this action exists.
//
// VALID_HANDLE / SECRET_VALUE are declared in aes_actions_validate_test.go
// (same package).
package proto

import (
	"strings"
	"testing"
)

func TestGroupEncryptWithAAD_Validate_RejectsInvalidPlaintext(t *testing.T) {
	r := GroupEncryptWithAADRequest{
		GroupHandle:  VALID_HANDLE,
		PlaintextB64: "!!!not-base64!!!",
		AADB64:       "aGVsbG8=",
	}
	err := r.Validate()
	if err == nil {
		t.Fatalf("expected validation error for invalid Base64 plaintext")
	}
	if !strings.Contains(err.Error(), "plaintext_b64") {
		t.Fatalf("error must mention field, got %q", err.Error())
	}
}

func TestGroupEncryptWithAAD_Validate_RejectsBadHandle(t *testing.T) {
	r := GroupEncryptWithAADRequest{
		GroupHandle:  "", // too short / empty
		PlaintextB64: "aGVsbG8=",
		AADB64:       "aGVsbG8=",
	}
	err := r.Validate()
	if err == nil {
		t.Fatalf("expected validation error for empty handle")
	}
	if !strings.Contains(err.Error(), "group_handle") {
		t.Fatalf("error must mention field, got %q", err.Error())
	}
}

// TestGroupEncryptWithAAD_Validate_RejectsEmptyAAD — the whole point of this
// action is to bind an AAD, so an empty AAD is rejected (plain group_encrypt
// covers the no-AAD case).
func TestGroupEncryptWithAAD_Validate_RejectsEmptyAAD(t *testing.T) {
	r := GroupEncryptWithAADRequest{
		GroupHandle:  VALID_HANDLE,
		PlaintextB64: "aGVsbG8=",
		AADB64:       "",
	}
	err := r.Validate()
	if err == nil {
		t.Fatalf("expected validation error for empty aad_b64")
	}
	if !strings.Contains(err.Error(), "aad_b64") {
		t.Fatalf("error must mention field, got %q", err.Error())
	}
}

func TestGroupEncryptWithAAD_Validate_DoesNotEchoSecretInError(t *testing.T) {
	// On validation failure the error message must not echo the input.
	r := GroupEncryptWithAADRequest{
		GroupHandle:  "", // forces validation failure before plaintext is checked
		PlaintextB64: SECRET_VALUE,
		AADB64:       "aGVsbG8=",
	}
	err := r.Validate()
	if err == nil {
		t.Fatalf("expected error")
	}
	if strings.Contains(err.Error(), "SUPER_SECRET") {
		t.Fatalf("validation error must not echo input value, got %q", err.Error())
	}
}
