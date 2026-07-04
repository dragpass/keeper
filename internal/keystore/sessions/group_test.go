// Group DEK opaque handle store regression guard.
//
// **Defects this test catches:**
//   - Open failing to retain raw bytes in the store → subsequent Use fails
//     and breaks every aes_* action
//   - Missing expiry check → a 15-minute-old handle is still usable →
//     opaque-handle surface regression
//   - Close becoming non-idempotent → panic / double-free on second call
//   - Handle ID collisions (weak rand) → may reference another user's key
//   - Concurrent-use race → memguard buffer use-after-destroy

package sessions

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"sync"
	"testing"
	"time"
)

func TestGroupSession_Open_ReturnsValidHandle(t *testing.T) {
	store := NewGroupSessionStore(15 * time.Minute)
	raw := mustRandKey(t)

	handle, expiresAt, err := store.Open(raw)
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	// handle format: 32B → Base64 44 chars
	decoded, err := base64.StdEncoding.DecodeString(handle)
	if err != nil {
		t.Errorf("handle should be valid base64: %v", err)
	}
	if len(decoded) != 32 {
		t.Errorf("handle decoded length = %d, want 32", len(decoded))
	}

	// expires_at must be in the future
	if !expiresAt.After(time.Now()) {
		t.Errorf("expires_at should be in the future: %v", expiresAt)
	}

	if got := store.Size(); got != 1 {
		t.Errorf("store size = %d, want 1", got)
	}
}

func TestGroupSession_Open_RejectsBadKeyLength(t *testing.T) {
	store := NewGroupSessionStore(15 * time.Minute)
	for _, n := range []int{0, 1, 16, 31, 33, 64} {
		_, _, err := store.Open(make([]byte, n))
		if err == nil {
			t.Errorf("Open should reject %dB key", n)
		}
	}
}

func TestGroupSession_Use_PassesRawBytesToCallback(t *testing.T) {
	store := NewGroupSessionStore(15 * time.Minute)
	raw := mustRandKey(t)
	rawCopy := make([]byte, 32)
	copy(rawCopy, raw)

	handle, _, err := store.Open(raw) // store takes ownership of raw
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	useErr := store.Use(handle, func(dek []byte) error {
		if len(dek) != 32 {
			t.Errorf("callback dek length = %d, want 32", len(dek))
		}
		if !bytes.Equal(dek, rawCopy) {
			t.Error("callback dek should match original raw bytes")
		}
		return nil
	})
	if useErr != nil {
		t.Errorf("Use returned error: %v", useErr)
	}
}

func TestGroupSession_Close_RemovesEntry(t *testing.T) {
	store := NewGroupSessionStore(15 * time.Minute)
	handle, _, _ := store.Open(mustRandKey(t))

	if got := store.Size(); got != 1 {
		t.Fatalf("size before close = %d, want 1", got)
	}

	store.Close(handle)

	if got := store.Size(); got != 0 {
		t.Errorf("size after close = %d, want 0", got)
	}

	// subsequent Use is NotFound
	useErr := store.Use(handle, func(_ []byte) error { return nil })
	if useErr != ErrGroupSessionNotFound {
		t.Errorf("Use after close: got %v, want ErrGroupSessionNotFound", useErr)
	}
}

func TestGroupSession_Close_IsIdempotent(t *testing.T) {
	store := NewGroupSessionStore(15 * time.Minute)
	handle, _, _ := store.Open(mustRandKey(t))

	store.Close(handle)
	// A second Close must be a no-op without panic.
	store.Close(handle)
	store.Close("never-existed")

	if got := store.Size(); got != 0 {
		t.Errorf("unexpected entries: %d", got)
	}
}

func TestGroupSession_Use_RejectsExpiredHandle(t *testing.T) {
	store := NewGroupSessionStore(15 * time.Minute)
	handle, _, _ := store.Open(mustRandKey(t))

	// jump the clock 1h into the future → trigger expiry
	store.SetClock(func() time.Time { return time.Now().Add(1 * time.Hour) })

	err := store.Use(handle, func(_ []byte) error { return nil })
	if err != ErrGroupSessionExpired {
		t.Errorf("expected ErrGroupSessionExpired, got %v", err)
	}

	// lazy-evict → size 0
	if got := store.Size(); got != 0 {
		t.Errorf("expired entry should be evicted, size = %d", got)
	}
}

func TestGroupSession_Status_ReturnsTTL(t *testing.T) {
	ttl := 10 * time.Minute
	store := NewGroupSessionStore(ttl)
	handle, _, _ := store.Open(mustRandKey(t))

	exists, remaining := store.Status(handle)
	if !exists {
		t.Fatal("Status should report existing handle")
	}
	// remaining should be near ttl ms (we just opened)
	expectedMs := ttl.Milliseconds()
	if remaining < expectedMs-1000 || remaining > expectedMs+100 {
		t.Errorf("remaining = %d ms, want ~%d ms", remaining, expectedMs)
	}

	// nonexistent handle
	exists, remaining = store.Status("never-existed")
	if exists || remaining != 0 {
		t.Errorf("nonexistent handle: got (exists=%v, remaining=%d), want (false, 0)", exists, remaining)
	}
}

func TestGroupSession_Reap_RemovesExpiredOnly(t *testing.T) {
	store := NewGroupSessionStore(15 * time.Minute)
	handle1, _, _ := store.Open(mustRandKey(t))
	handle2, _, _ := store.Open(mustRandKey(t))

	if got := store.Size(); got != 2 {
		t.Fatalf("size before reap = %d, want 2", got)
	}

	// move clock → both expired
	store.SetClock(func() time.Time { return time.Now().Add(20 * time.Minute) })

	removed := store.Reap()
	if removed != 2 {
		t.Errorf("Reap removed = %d, want 2", removed)
	}
	if got := store.Size(); got != 0 {
		t.Errorf("size after reap = %d, want 0", got)
	}

	// Subsequent Use is NotFound (Reap also destroyed the entries).
	for _, h := range []string{handle1, handle2} {
		err := store.Use(h, func(_ []byte) error { return nil })
		if err != ErrGroupSessionNotFound {
			t.Errorf("post-reap Use: got %v, want NotFound", err)
		}
	}
}

func TestGroupSession_ConcurrentUseIsSafe(t *testing.T) {
	// Running with the race detector (`go test -race`) catches missing mutexes.
	store := NewGroupSessionStore(15 * time.Minute)
	handle, _, _ := store.Open(mustRandKey(t))

	const N = 50
	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func() {
			defer wg.Done()
			err := store.Use(handle, func(dek []byte) error {
				// Costs roughly one AES-GCM op. Simple read.
				if len(dek) != 32 {
					t.Errorf("unexpected dek length: %d", len(dek))
				}
				return nil
			})
			if err != nil {
				t.Errorf("concurrent Use error: %v", err)
			}
		}()
	}
	wg.Wait()
}

func TestGroupSession_HandleIDsAreUnique(t *testing.T) {
	// 32B random base → collision probability ~1/2^256. After 100 issues,
	// confirm 0 duplicates.
	store := NewGroupSessionStore(15 * time.Minute)
	seen := make(map[string]bool, 100)
	for i := 0; i < 100; i++ {
		handle, _, err := store.Open(mustRandKey(t))
		if err != nil {
			t.Fatalf("open #%d: %v", i, err)
		}
		if seen[handle] {
			t.Errorf("duplicate handle: %s", handle)
		}
		seen[handle] = true
	}
	if got := store.Size(); got != 100 {
		t.Errorf("size = %d, want 100", got)
	}
}

func TestGroupSession_Reaper_StartStop(t *testing.T) {
	store := NewGroupSessionStore(15 * time.Minute)
	// Stop via defer to avoid a goroutine leak.
	store.StartReaper(50 * time.Millisecond)
	defer store.StopReaper()

	// Verify the reaper runs over an idle store without panicking.
	time.Sleep(150 * time.Millisecond)

	// A second start must be a no-op via sync.Once.
	store.StartReaper(50 * time.Millisecond)
}

func mustRandKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return key
}
