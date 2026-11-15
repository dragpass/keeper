package keystore

import (
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/testdouble"
)

// The Extension keeps its device-wide archive_key_generate over Native
// Messaging (its E2E org fixture). The org-scoped form is the App's: a
// Native frame that names an org is refused before the handler, so an
// Extension or a proxied host cannot create org slots (lv96).
func TestNativeArchiveKeyGenerateWithOrgIsRefused(t *testing.T) {
	app, _, store := newLeaseApp(t)
	frame := func(payload string) []byte {
		b, _ := json.Marshal(map[string]any{"action": proto.ActionArchiveKeyGenerate, "request_id": "g", "payload": json.RawMessage(payload)})
		return b
	}
	before := store.calls.Load()
	refused := app.HandleRequest(frame(`{"org_id":"33333333-3333-4333-8333-333333333333"}`))
	if refused.Success || refused.ErrorCode != ErrCodeChatAppCallerRequired || refused.RequestID != "g" {
		t.Fatalf("org-scoped generate over Native Messaging: %+v", refused)
	}
	if store.calls.Load() != before {
		t.Fatal("a refused Native org generate touched the keychain")
	}
	if device := app.HandleRequest(frame(`{}`)); !device.Success {
		t.Fatalf("device-wide generate over Native Messaging: %+v", device)
	}
	if org := app.HandleAppRequest(sessionA, "", frame(`{"org_id":"33333333-3333-4333-8333-333333333333"}`)); !org.Success {
		t.Fatalf("org generate from the App: %+v", org)
	}
}

// spyStore records every keychain access by operation and account.
type spyStore struct {
	SecretStore
	mu     sync.Mutex
	access []string
}

func (s *spyStore) record(op, account string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.access = append(s.access, op+" "+account)
}

func (s *spyStore) Get(service, account string) (string, error) {
	s.record("get", account)
	return s.SecretStore.Get(service, account)
}

func (s *spyStore) Set(service, account, value string) error {
	s.record("set", account)
	return s.SecretStore.Set(service, account, value)
}

func (s *spyStore) Delete(service, account string) error {
	s.record("delete", account)
	return s.SecretStore.Delete(service, account)
}

func (s *spyStore) take() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.access
	s.access = nil
	return out
}

// The refusal happens before any keychain access: not one slot is read or
// written, for a named org or an empty org_id (lv96 review).
func TestNativeArchiveKeyGenerateWithOrgTouchesNoKeychainSlot(t *testing.T) {
	store := &spyStore{SecretStore: testdouble.NewMemorySecretStore()}
	app := NewApp(Deps{Store: store, Clock: func() time.Time { return time.Unix(1_800_000_000, 0) }})
	for _, payload := range []string{`{"org_id":"33333333-3333-4333-8333-333333333333"}`, `{"org_id":""}`} {
		store.take()
		frame, _ := json.Marshal(map[string]any{"action": proto.ActionArchiveKeyGenerate, "request_id": "g", "payload": json.RawMessage(payload)})
		refused := app.HandleRequest(frame)
		if refused.Success || refused.ErrorCode != ErrCodeChatAppCallerRequired {
			t.Fatalf("%s over Native Messaging: %+v", payload, refused)
		}
		if got := store.take(); len(got) != 0 {
			t.Fatalf("%s over Native Messaging touched the keychain: %v", payload, got)
		}
	}
}
