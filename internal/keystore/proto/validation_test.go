package proto

import (
	"errors"
	"strings"
	"testing"
)

func TestRequireString(t *testing.T) {
	if err := requireString("hello", "field"); err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
	if err := requireString("", "user_alias"); err == nil {
		t.Fatalf("expected error for empty string")
	} else if !strings.Contains(err.Error(), "user_alias") {
		t.Fatalf("error must include field name, got %q", err.Error())
	}
}

func TestRequireBase64(t *testing.T) {
	// std base64 round-trip.
	decoded, err := requireBase64("aGVsbG8=", "payload")
	if err != nil {
		t.Fatalf("std base64 failed: %v", err)
	}
	if string(decoded) != "hello" {
		t.Fatalf("decoded = %q", decoded)
	}

	// URL-safe variant.
	if _, err := requireBase64("aGVsbG8", "payload"); err != nil {
		t.Fatalf("rawurl base64 failed: %v", err)
	}

	// Reject empty.
	if _, err := requireBase64("", "payload"); err == nil {
		t.Fatalf("expected error for empty")
	}

	// Reject invalid.
	if _, err := requireBase64("!!!not-base64!!!", "payload"); err == nil {
		t.Fatalf("expected error for invalid base64")
	}
}

func TestRequireBase64Len(t *testing.T) {
	// 32B (AES key) — "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" decode to 32 bytes? Let's compute.
	// Actually: 32 bytes of 0x00 = base64 "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" (44 chars).
	zeros32 := strings.Repeat("A", 43) + "="
	decoded, err := requireBase64Len(zeros32, "key", 32)
	if err != nil {
		t.Fatalf("32B decode failed: %v", err)
	}
	if len(decoded) != 32 {
		t.Fatalf("expected 32B, got %d", len(decoded))
	}

	// Reject on length mismatch.
	if _, err := requireBase64Len(zeros32, "key", 16); err == nil {
		t.Fatalf("expected length mismatch error")
	} else if !strings.Contains(err.Error(), "32") {
		t.Fatalf("error must include actual length, got %q", err.Error())
	}
}

func TestRequireHandle(t *testing.T) {
	// 32B Base64 = 44 chars typical.
	valid := strings.Repeat("A", 43) + "="
	if err := requireHandle(valid, "group_handle"); err != nil {
		t.Fatalf("expected valid handle, got %v", err)
	}

	// Empty.
	if err := requireHandle("", "group_handle"); err == nil {
		t.Fatalf("expected error for empty")
	}

	// Handle too short.
	if err := requireHandle("short", "group_handle"); err == nil {
		t.Fatalf("expected error for short handle")
	}

	// Handle too long.
	if err := requireHandle(strings.Repeat("A", 100), "group_handle"); err == nil {
		t.Fatalf("expected error for long handle")
	}

	// Contains whitespace.
	if err := requireHandle("AAAA AAAA"+strings.Repeat("A", 35), "group_handle"); err == nil {
		t.Fatalf("expected error for whitespace handle")
	}
}

func TestRequirePositiveVersion(t *testing.T) {
	if err := requirePositiveVersion(1, "dek_version"); err != nil {
		t.Fatalf("expected valid version 1, got %v", err)
	}
	if err := requirePositiveVersion(0, "dek_version"); err == nil {
		t.Fatalf("expected error for version 0")
	}
	if err := requirePositiveVersion(-3, "dek_version"); err == nil {
		t.Fatalf("expected error for negative version")
	}
}

func TestRequirePEM(t *testing.T) {
	pem := "-----BEGIN PRIVATE KEY-----\nABCD\n-----END PRIVATE KEY-----"
	if err := requirePEM(pem, "key"); err != nil {
		t.Fatalf("valid PEM rejected: %v", err)
	}
	if err := requirePEM("not a pem", "key"); err == nil {
		t.Fatalf("expected error for non-PEM")
	}
	if err := requirePEM("", "key"); err == nil {
		t.Fatalf("expected error for empty")
	}
	// leading whitespace should still pass.
	if err := requirePEM("\n\n  -----BEGIN X-----", "key"); err != nil {
		t.Fatalf("PEM with leading whitespace rejected: %v", err)
	}
}

func TestValidationErrorEcho(t *testing.T) {
	// Regression guard: helper error messages must not echo the input value.
	const sensitiveValue = "SUPER_SECRET_BASE64_DO_NOT_LEAK"
	_, err := requireBase64Len(sensitiveValue+"==", "wrapped_dek", 32)
	if err == nil {
		t.Fatalf("expected error")
	}
	if strings.Contains(err.Error(), "SUPER_SECRET") {
		t.Fatalf("error message must not echo input value, got %q", err.Error())
	}
}

func TestIsValidationError(t *testing.T) {
	ve := newValidationError("field", "reason")
	if !IsValidationError(ve) {
		t.Fatalf("expected ValidationError detection")
	}
	if IsValidationError(errors.New("plain")) {
		t.Fatalf("plain error should not be ValidationError")
	}
}
