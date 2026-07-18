package sessions

import (
	"errors"
	"testing"
)

func TestRecoveryKeySessionStoreKeepsKeyBehindHandle(t *testing.T) {
	store := NewRecoveryKeySessionStore(RecoveryKeySessionTTL)
	handle, _, err := store.Open([]byte("ABCD-EFGH-JKLM-NPQR-STUV-WXYZ"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer store.Close(handle)

	var got string
	if err := store.Use(handle, func(raw []byte) error {
		got = string(raw)
		return nil
	}); err != nil {
		t.Fatalf("Use: %v", err)
	}
	if got != "ABCD-EFGH-JKLM-NPQR-STUV-WXYZ" {
		t.Fatalf("key = %q", got)
	}
}

func TestRecoveryKeySessionStoreRejectsInvalidKey(t *testing.T) {
	store := NewRecoveryKeySessionStore(RecoveryKeySessionTTL)
	if _, _, err := store.Open([]byte("invalid")); err == nil {
		t.Fatal("Open should reject an invalid recovery key")
	}
	if err := store.Use("missing", func([]byte) error { return nil }); !errors.Is(err, ErrRecoveryKeySessionNotFound) {
		t.Fatalf("Use missing = %v", err)
	}
}
