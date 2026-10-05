// personal_dek_adopt_test.go — the adopt check and write hold the keychain
// process lock, so a sign-out or a login that starts while an adoption is
// deciding lands after its write, never between the check and the write.

package keychain

import (
	"errors"
	"testing"
	"time"

	"github.com/dragpass/keeper/config"
)

func seedAdoptDeviceKey(t *testing.T, store SecretStore) {
	t.Helper()
	if err := store.Set(config.Service, config.DeviceKey, "device-key-b64"); err != nil {
		t.Fatalf("seed device key: %v", err)
	}
}

func slotValue(t *testing.T, store SecretStore) string {
	t.Helper()
	value, err := GetPersonalDeviceWrappedDEK(store)
	if errors.Is(err, ErrSecretNotFound) {
		return ""
	}
	if err != nil {
		t.Fatalf("read slot: %v", err)
	}
	return value
}

func acceptAll(string) error { return nil }

func TestAdoptPersonalDeviceWrappedDEK_Outcomes(t *testing.T) {
	t.Run("empty slot is filled", func(t *testing.T) {
		store := NewMemorySecretStore()
		seedAdoptDeviceKey(t, store)
		var seenKey string
		outcome, err := AdoptPersonalDeviceWrappedDEK(store, "copy", func(key string) error {
			seenKey = key
			return nil
		})
		if err != nil || outcome != AdoptStored {
			t.Fatalf("outcome=%v err=%v", outcome, err)
		}
		if seenKey != "device-key-b64" {
			t.Fatalf("opens got %q, want the stored device key", seenKey)
		}
		if got := slotValue(t, store); got != "copy" {
			t.Fatalf("slot = %q", got)
		}
	})
	t.Run("signed out is skipped before anything is checked", func(t *testing.T) {
		store := NewMemorySecretStore()
		seedAdoptDeviceKey(t, store)
		if _, _, err := SignOutDevice(store); err != nil {
			t.Fatalf("signout: %v", err)
		}
		outcome, err := AdoptPersonalDeviceWrappedDEK(store, "copy", func(string) error {
			t.Fatal("opens must not run for a signed-out device")
			return nil
		})
		if err != nil || outcome != AdoptSkippedSignedOut {
			t.Fatalf("outcome=%v err=%v", outcome, err)
		}
		if got := slotValue(t, store); got != "" {
			t.Fatalf("slot = %q, want empty", got)
		}
	})
	t.Run("occupied slot is kept", func(t *testing.T) {
		store := NewMemorySecretStore()
		seedAdoptDeviceKey(t, store)
		if err := SavePersonalDeviceWrappedDEK(store, "fresh"); err != nil {
			t.Fatal(err)
		}
		outcome, err := AdoptPersonalDeviceWrappedDEK(store, "stale", acceptAll)
		if err != nil || outcome != AdoptSkippedSlotOccupied {
			t.Fatalf("outcome=%v err=%v", outcome, err)
		}
		if got := slotValue(t, store); got != "fresh" {
			t.Fatalf("slot = %q, want fresh", got)
		}
	})
	t.Run("no device key", func(t *testing.T) {
		store := NewMemorySecretStore()
		if _, err := AdoptPersonalDeviceWrappedDEK(store, "copy", acceptAll); !errors.Is(err, ErrNoDeviceKey) {
			t.Fatalf("err = %v, want ErrNoDeviceKey", err)
		}
		if got := slotValue(t, store); got != "" {
			t.Fatalf("slot = %q", got)
		}
	})
	t.Run("a wrap opens refuses is not written", func(t *testing.T) {
		store := NewMemorySecretStore()
		seedAdoptDeviceKey(t, store)
		refused := errors.New("does not open")
		if _, err := AdoptPersonalDeviceWrappedDEK(store, "copy", func(string) error { return refused }); !errors.Is(err, refused) {
			t.Fatalf("err = %v", err)
		}
		if got := slotValue(t, store); got != "" {
			t.Fatalf("slot = %q", got)
		}
	})
}

// raceInsideAdopt starts other while adopt is between its check and its
// write, and confirms other does not finish until adopt has returned.
func raceInsideAdopt(t *testing.T, store SecretStore, other func() error) {
	t.Helper()
	otherDone := make(chan error, 1)
	outcome, err := AdoptPersonalDeviceWrappedDEK(store, "stale-copy", func(string) error {
		go func() { otherDone <- other() }()
		select {
		case err := <-otherDone:
			t.Errorf("a concurrent writer finished inside the adopt critical section (err=%v)", err)
		case <-time.After(100 * time.Millisecond):
		}
		return nil
	})
	if err != nil || outcome != AdoptStored {
		t.Fatalf("adopt outcome=%v err=%v", outcome, err)
	}
	select {
	case err := <-otherDone:
		if err != nil {
			t.Fatalf("concurrent writer: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("concurrent writer never ran")
	}
}

func TestAdoptPersonalDeviceWrappedDEK_SignOutLandsAfterTheWrite(t *testing.T) {
	store := NewMemorySecretStore()
	seedAdoptDeviceKey(t, store)
	raceInsideAdopt(t, store, func() error {
		_, _, err := SignOutDevice(store)
		return err
	})
	if got := slotValue(t, store); got != "" {
		t.Fatalf("slot = %q after the sign-out; the adoption undid it", got)
	}
	binding, _, err := GetAccountBinding(store)
	if err != nil || !binding.SignedOut {
		t.Fatalf("binding = %+v, err = %v", binding, err)
	}
}

func TestAdoptPersonalDeviceWrappedDEK_LoginLandsAfterTheWrite(t *testing.T) {
	store := NewMemorySecretStore()
	seedAdoptDeviceKey(t, store)
	raceInsideAdopt(t, store, func() error {
		return SavePersonalDeviceWrappedDEK(store, "login-wrap")
	})
	if got := slotValue(t, store); got != "login-wrap" {
		t.Fatalf("slot = %q, want the login's wrap", got)
	}
}
