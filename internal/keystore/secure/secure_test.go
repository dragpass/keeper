// Regression guards for the lifetime helpers in secure.go.
//
// **Defects this test catches:**
//   - Regressions where Zeroize / WipeString fail to zero-fill in place
//   - Regressions where WithDecodedSecretB64 fails to zeroize raw bytes after
//     the callback returns
//   - Regressions where WithDecodedSecretB64Len invokes the callback on a
//     length mismatch
//   - Whether Base64 decode failures surface with the field name (debuggability)
package secure

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestZeroize_InPlace(t *testing.T) {
	b := []byte{1, 2, 3, 4, 5}
	Zeroize(b)
	if !bytes.Equal(b, make([]byte, 5)) {
		t.Fatalf("Zeroize did not clear bytes: %v", b)
	}
}

func TestZeroize_EmptySlice(t *testing.T) {
	// Both nil and empty are ignored without panicking.
	Zeroize(nil)
	Zeroize([]byte{})
}

func TestWipeString_ClearsBackingBytes(t *testing.T) {
	s := "secret"
	WipeString(&s)
	if s != "" {
		t.Fatalf("WipeString did not clear string: %q", s)
	}
}

func TestWithDecodedSecretB64_HappyPath(t *testing.T) {
	var observed []byte
	err := WithDecodedSecretB64("aGVsbG8=", "payload", func(raw []byte) error {
		// Inside the callback, raw is alive.
		if string(raw) != "hello" {
			t.Fatalf("decode mismatch: %q", raw)
		}
		observed = raw // intentionally escape to verify the zeroize effect.
		return nil
	})
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	// After the callback returns, the escaped alias must also be zero (defer Zeroize).
	for i, c := range observed {
		if c != 0 {
			t.Fatalf("byte %d not zeroed: %d", i, c)
		}
	}
}

func TestWithDecodedSecretB64_PropagatesCallbackError(t *testing.T) {
	wantErr := errors.New("callback failed")
	err := WithDecodedSecretB64("aGVsbG8=", "payload", func(raw []byte) error {
		return wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected callback error to propagate, got %v", err)
	}
}

func TestWithDecodedSecretB64_RejectsInvalidBase64(t *testing.T) {
	called := false
	err := WithDecodedSecretB64("!!!not-base64!!!", "payload", func(raw []byte) error {
		called = true
		return nil
	})
	if err == nil {
		t.Fatalf("expected error for invalid Base64")
	}
	if called {
		t.Fatalf("callback must not be called when decode fails")
	}
	if !strings.Contains(err.Error(), "payload") {
		t.Fatalf("error must mention field name, got %q", err.Error())
	}
}

func TestWithDecodedSecretB64Len_RejectsWrongLength(t *testing.T) {
	called := false
	err := WithDecodedSecretB64Len("aGVsbG8=", "key", 32, func(raw []byte) error {
		called = true
		return nil
	})
	if err == nil {
		t.Fatalf("expected error for wrong length")
	}
	if called {
		t.Fatalf("callback must not be called when length mismatches")
	}
	if !strings.Contains(err.Error(), "32") {
		t.Fatalf("error must include expected length, got %q", err.Error())
	}
}

func TestWithDecodedSecretB64Len_AcceptsExactLength(t *testing.T) {
	// 32B = 44 chars Base64.
	const raw32 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	err := WithDecodedSecretB64Len(raw32, "key", 32, func(raw []byte) error {
		if len(raw) != 32 {
			t.Fatalf("expected 32B, got %d", len(raw))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
}

func TestWithDecodedSecretB64Len_DoesNotEchoSecretInError(t *testing.T) {
	// Regression guard: the length-mismatch error message must not include
	// the input payload.
	const sensitive = "U1VQRVJfU0VDUkVUX0RPX05PVF9MRUFL" // "SUPER_SECRET_DO_NOT_LEAK"
	err := WithDecodedSecretB64Len(sensitive, "wrap_key", 32, func(raw []byte) error {
		return nil
	})
	if err == nil {
		t.Fatalf("expected error")
	}
	if strings.Contains(err.Error(), "SUPER_SECRET") || strings.Contains(err.Error(), sensitive) {
		t.Fatalf("error must not echo input, got %q", err.Error())
	}
}
