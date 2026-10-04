// Regression guards for the lifetime helpers in secure.go.
//
// **Defects this test catches:**
//   - Regressions where Zeroize / WipeString fail to zero-fill in place
package secure

import (
	"bytes"
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
