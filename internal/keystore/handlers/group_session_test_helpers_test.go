package handlers

import (
	"crypto/rand"
	"testing"
)

func openSessionForFreshKey(t *testing.T, deps Deps) (handle string, raw []byte) {
	t.Helper()
	raw = make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatalf("rand: %v", err)
	}
	rawCopy := append([]byte(nil), raw...)
	handle, _, err := deps.GroupSessions.Open(rawCopy)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() {
		deps.GroupSessions.Close(handle)
	})
	return handle, raw
}
