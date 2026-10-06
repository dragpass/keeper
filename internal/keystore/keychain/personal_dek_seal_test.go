// personal_dek_seal_test.go — the login's device wrap reads the device key
// and writes the slot in one hold of the keychain process lock, so a device
// key rotation cannot land between the read and the write and leave the slot
// sealed under a key that is no longer stored.

package keychain

import (
	"errors"
	"testing"
	"time"
)

func TestSealPersonalDeviceWrappedDEK_SealsUnderTheStoredKey(t *testing.T) {
	store := NewMemorySecretStore()
	seedAdoptDeviceKey(t, store)
	var seenKey string
	wrapped, err := SealPersonalDeviceWrappedDEK(store, func(key string) (string, error) {
		seenKey = key
		return "wrap-under-" + key, nil
	})
	if err != nil || wrapped != "wrap-under-device-key-b64" {
		t.Fatalf("wrapped=%q err=%v", wrapped, err)
	}
	if seenKey != "device-key-b64" {
		t.Fatalf("seal got %q, want the stored device key", seenKey)
	}
	if got := slotValue(t, store); got != wrapped {
		t.Fatalf("slot = %q", got)
	}
}

func TestSealPersonalDeviceWrappedDEK_NoDeviceKey(t *testing.T) {
	store := NewMemorySecretStore()
	_, err := SealPersonalDeviceWrappedDEK(store, func(string) (string, error) {
		t.Fatal("seal ran without a device key")
		return "", nil
	})
	if !errors.Is(err, ErrNoDeviceKey) {
		t.Fatalf("err = %v", err)
	}
}

func TestSealPersonalDeviceWrappedDEK_SealErrorWritesNothing(t *testing.T) {
	store := NewMemorySecretStore()
	seedAdoptDeviceKey(t, store)
	refused := errors.New("seal failed")
	if _, err := SealPersonalDeviceWrappedDEK(store, func(string) (string, error) { return "", refused }); !errors.Is(err, refused) {
		t.Fatalf("err = %v", err)
	}
	if got := slotValue(t, store); got != "" {
		t.Fatalf("slot = %q", got)
	}
}

// A device key rotation that starts while the wrap is being sealed waits for
// the write, then sees a slot it did not read and refuses, so the stored key
// and the stored wrap still belong together.
func TestSealPersonalDeviceWrappedDEK_RotationLandsAfterTheWrite(t *testing.T) {
	store := NewMemorySecretStore()
	seedAdoptDeviceKey(t, store)
	if err := SavePersonalDeviceWrappedDEK(store, "old-wrap"); err != nil {
		t.Fatal(err)
	}
	rotated := make(chan error, 1)
	_, err := SealPersonalDeviceWrappedDEK(store, func(key string) (string, error) {
		go func() {
			rotated <- CommitPersonalKeyBundleRotation(store, key, "old-wrap", "new-device-key", "old-wrap-under-new-key")
		}()
		select {
		case err := <-rotated:
			t.Errorf("a device key rotation finished inside the seal critical section (err=%v)", err)
		case <-time.After(100 * time.Millisecond):
		}
		return "login-wrap-under-" + key, nil
	})
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	select {
	case err := <-rotated:
		if err == nil {
			t.Fatal("the rotation committed over a slot it did not read")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the rotation never ran")
	}
	key, err := GetDeviceKey(store)
	if err != nil || key != "device-key-b64" {
		t.Fatalf("device key = %q, err = %v", key, err)
	}
	if got := slotValue(t, store); got != "login-wrap-under-device-key-b64" {
		t.Fatalf("slot = %q", got)
	}
}
