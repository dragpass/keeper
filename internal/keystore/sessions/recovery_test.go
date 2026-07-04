// Recovery PEM opaque handle store regression guard.
//
// **Defects this test catches:**
//   - Open failing to retain PEM bytes → subsequent Use fails → both
//     recoverysign and dek_rewrap_with_old_key break
//   - Missing expiry check → a 5-minute-old handle is still usable →
//     opaque-handle surface regression
//   - Close becoming non-idempotent → double-free panic
//   - Concurrent-use race → memguard buffer use-after-destroy

package sessions

import (
	"bytes"
	"sync"
	"testing"
	"time"
)

const fakePEM = `-----BEGIN RSA PRIVATE KEY-----
fake-test-private-key-payload-only-content-matters-not-shape
-----END RSA PRIVATE KEY-----`

func TestRecoverySession_Open_ReturnsValidHandle(t *testing.T) {
	store := NewRecoverySessionStore(5 * time.Minute)
	handle, expiresAt, err := store.Open([]byte(fakePEM))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if handle == "" {
		t.Error("handle should not be empty")
	}
	if !expiresAt.After(time.Now()) {
		t.Errorf("expires_at should be in the future: %v", expiresAt)
	}
	if got := store.Size(); got != 1 {
		t.Errorf("store size = %d, want 1", got)
	}
}

func TestRecoverySession_Open_RejectsEmpty(t *testing.T) {
	store := NewRecoverySessionStore(5 * time.Minute)
	_, _, err := store.Open(nil)
	if err == nil {
		t.Error("Open should reject empty pem")
	}
	_, _, err = store.Open([]byte{})
	if err == nil {
		t.Error("Open should reject 0-length pem")
	}
}

func TestRecoverySession_Use_PassesPEMToCallback(t *testing.T) {
	store := NewRecoverySessionStore(5 * time.Minute)
	pemCopy := []byte(fakePEM)
	original := []byte(fakePEM) // separate copy for comparison

	handle, _, err := store.Open(pemCopy) // store takes ownership
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	useErr := store.Use(handle, func(pem []byte) error {
		if !bytes.Equal(pem, original) {
			t.Errorf("callback pem should match original")
		}
		return nil
	})
	if useErr != nil {
		t.Errorf("Use returned error: %v", useErr)
	}
}

func TestRecoverySession_Close_RemovesEntry(t *testing.T) {
	store := NewRecoverySessionStore(5 * time.Minute)
	handle, _, _ := store.Open([]byte(fakePEM))

	if got := store.Size(); got != 1 {
		t.Fatalf("size before close = %d, want 1", got)
	}

	store.Close(handle)

	if got := store.Size(); got != 0 {
		t.Errorf("size after close = %d, want 0", got)
	}

	useErr := store.Use(handle, func(_ []byte) error { return nil })
	if useErr != ErrRecoverySessionNotFound {
		t.Errorf("Use after close: got %v, want ErrRecoverySessionNotFound", useErr)
	}
}

func TestRecoverySession_Close_IsIdempotent(t *testing.T) {
	store := NewRecoverySessionStore(5 * time.Minute)
	handle, _, _ := store.Open([]byte(fakePEM))

	store.Close(handle)
	store.Close(handle) // second call must also not panic
	store.Close("never-existed")

	if got := store.Size(); got != 0 {
		t.Errorf("unexpected entries: %d", got)
	}
}

func TestRecoverySession_Use_RejectsExpired(t *testing.T) {
	store := NewRecoverySessionStore(5 * time.Minute)
	handle, _, _ := store.Open([]byte(fakePEM))

	store.SetClock(func() time.Time { return time.Now().Add(10 * time.Minute) })

	err := store.Use(handle, func(_ []byte) error { return nil })
	if err != ErrRecoverySessionExpired {
		t.Errorf("expected ErrRecoverySessionExpired, got %v", err)
	}
	if got := store.Size(); got != 0 {
		t.Errorf("expired entry should be evicted, size = %d", got)
	}
}

func TestRecoverySession_Reap_RemovesExpired(t *testing.T) {
	store := NewRecoverySessionStore(5 * time.Minute)
	handle1, _, _ := store.Open([]byte(fakePEM))
	handle2, _, _ := store.Open([]byte(fakePEM + "-2"))

	store.SetClock(func() time.Time { return time.Now().Add(10 * time.Minute) })

	removed := store.Reap()
	if removed != 2 {
		t.Errorf("Reap removed = %d, want 2", removed)
	}

	for _, h := range []string{handle1, handle2} {
		err := store.Use(h, func(_ []byte) error { return nil })
		if err != ErrRecoverySessionNotFound {
			t.Errorf("post-reap Use: got %v, want NotFound", err)
		}
	}
}

func TestRecoverySession_Status_ReturnsTTL(t *testing.T) {
	ttl := 5 * time.Minute
	store := NewRecoverySessionStore(ttl)
	handle, _, _ := store.Open([]byte(fakePEM))

	exists, remaining := store.Status(handle)
	if !exists {
		t.Fatal("Status should report existing handle")
	}
	expectedMs := ttl.Milliseconds()
	if remaining < expectedMs-1000 || remaining > expectedMs+100 {
		t.Errorf("remaining = %d ms, want ~%d ms", remaining, expectedMs)
	}

	exists, remaining = store.Status("nonexistent")
	if exists || remaining != 0 {
		t.Errorf("nonexistent: got (exists=%v, remaining=%d)", exists, remaining)
	}
}

func TestRecoverySession_ConcurrentUseIsSafe(t *testing.T) {
	store := NewRecoverySessionStore(5 * time.Minute)
	handle, _, _ := store.Open([]byte(fakePEM))

	const N = 50
	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func() {
			defer wg.Done()
			err := store.Use(handle, func(pem []byte) error {
				if len(pem) == 0 {
					t.Errorf("unexpected empty pem")
				}
				return nil
			})
			if err != nil {
				t.Errorf("concurrent Use: %v", err)
			}
		}()
	}
	wg.Wait()
}

func TestRecoverySession_HandleIDsAreUnique(t *testing.T) {
	store := NewRecoverySessionStore(5 * time.Minute)
	seen := make(map[string]bool, 50)
	for i := 0; i < 50; i++ {
		handle, _, err := store.Open([]byte(fakePEM))
		if err != nil {
			t.Fatalf("open #%d: %v", i, err)
		}
		if seen[handle] {
			t.Errorf("duplicate handle: %s", handle)
		}
		seen[handle] = true
	}
}

func TestRecoverySession_Reaper_StartStop(t *testing.T) {
	store := NewRecoverySessionStore(5 * time.Minute)
	store.StartReaper(50 * time.Millisecond)
	defer store.StopReaper()
	time.Sleep(150 * time.Millisecond)
	store.StartReaper(50 * time.Millisecond) // sync.Once → no-op
}
