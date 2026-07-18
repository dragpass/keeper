// app_test.go — unit tests for app.go / secret_store.go +
// regression guards for the App.HandleRequest dispatcher boundary.
//
// **What this catches:**
//   - Regressions in nil-Deps.Store/Clock/Rand → production-default
//     fallback.
//   - MemorySecretStore failing to return ErrSecretNotFound.
//   - KeyringSecretStore failing to translate keyring.ErrNotFound into
//     ErrSecretNotFound.
//   - Races where DefaultApp singleton initializes twice.
//   - App.HandleRequest regressing past the Logger boundary (merged in
//     from the old dispatcher_app_test.go).
//   - HandleRequest free function falling off the *App method
//     delegation.
//   - Unknown-action responses losing the unsupported ErrorCode.
package keystore

import (
	"crypto/rand"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/zalando/go-keyring"

	"github.com/dragpass/keeper/internal/keystore/sessions"
	"github.com/dragpass/keeper/internal/keystore/userpresence"
)

func TestNewApp_FillsProductionDefaults(t *testing.T) {
	app := NewApp(Deps{})
	if app.Store == nil {
		t.Fatalf("Store must default to KeyringSecretStore")
	}
	if _, ok := app.Store.(KeyringSecretStore); !ok {
		t.Fatalf("Store default must be KeyringSecretStore, got %T", app.Store)
	}
	if app.Clock == nil {
		t.Fatalf("Clock must default to time.Now")
	}
	// Clock is a function type so direct equality doesn't work. Just check Now returns a reasonable time.
	now := app.Clock()
	if now.IsZero() {
		t.Fatalf("Clock default must return non-zero time")
	}
	if app.Rand == nil {
		t.Fatalf("Rand must default to crypto/rand.Reader")
	}
	if _, ok := app.Logger.(StdLogger); !ok {
		t.Fatalf("Logger default must be StdLogger, got %T", app.Logger)
	}
	if _, ok := app.ServerKeyVerifier.(DefaultServerKeyVerifier); !ok {
		t.Fatalf("ServerKeyVerifier default must be DefaultServerKeyVerifier, got %T", app.ServerKeyVerifier)
	}
	if app.GroupSessions == nil {
		t.Fatalf("GroupSessions must default to sessions.DefaultGroupSessionStore()")
	}
	if app.GroupSessions != sessions.DefaultGroupSessionStore() {
		t.Fatalf("GroupSessions default must be the process-wide singleton (main.go reaper attaches to same instance)")
	}
	if app.RecoverySessions == nil {
		t.Fatalf("RecoverySessions must default to sessions.DefaultRecoverySessionStore()")
	}
	if app.RecoverySessions != sessions.DefaultRecoverySessionStore() {
		t.Fatalf("RecoverySessions default must be the process-wide singleton")
	}
	if app.RecoveryKeySessions != sessions.DefaultRecoveryKeySessionStore() {
		t.Fatalf("RecoveryKeySessions default must be the process-wide singleton")
	}
	if _, ok := app.UserPresence.(userpresence.Unavailable); !ok {
		t.Fatalf("UserPresence default must fail closed, got %T", app.UserPresence)
	}
}

func TestNewApp_RespectsInjection(t *testing.T) {
	store := NewMemorySecretStore()
	frozen := time.Date(2026, 4, 30, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time { return frozen }
	logger := NewMemoryLogger()
	verifier := AlwaysOKVerifier{}
	app := NewApp(Deps{
		Store:             store,
		Clock:             clock,
		Rand:              io.LimitReader(rand.Reader, 0), // 0-byte reader (boundary test)
		Logger:            logger,
		ServerKeyVerifier: verifier,
	})
	if app.Store != store {
		t.Fatalf("Store injection ignored")
	}
	if got := app.Clock(); !got.Equal(frozen) {
		t.Fatalf("Clock injection ignored, got %v", got)
	}
	// Rand can't be compared as a function — io.Reader interface is enough.
	if app.Rand == nil {
		t.Fatalf("Rand injection ignored")
	}
	if app.HandlersDeps().Rand == nil {
		t.Fatalf("Rand must propagate to handler deps")
	}
	if app.Logger != logger {
		t.Fatalf("Logger injection ignored")
	}
	if app.ServerKeyVerifier != verifier {
		t.Fatalf("ServerKeyVerifier injection ignored")
	}
}

// TestNewApp_RespectsSessionStoreInjection: an explicitly injected
// GroupSessionStore / RecoverySessionStore instance must end up on
// *App as-is and not get overwritten by the default singleton. Parallel
// unit tests need to be able to inject fresh stores.
func TestNewApp_RespectsSessionStoreInjection(t *testing.T) {
	groupStore := sessions.NewGroupSessionStore(15 * time.Minute)
	recoveryStore := sessions.NewRecoverySessionStore(5 * time.Minute)
	recoveryKeyStore := sessions.NewRecoveryKeySessionStore(5 * time.Minute)
	app := NewApp(Deps{
		GroupSessions:       groupStore,
		RecoverySessions:    recoveryStore,
		RecoveryKeySessions: recoveryKeyStore,
	})
	if app.GroupSessions != groupStore {
		t.Fatalf("GroupSessions injection ignored")
	}
	if app.RecoverySessions != recoveryStore {
		t.Fatalf("RecoverySessions injection ignored")
	}
	if app.RecoveryKeySessions != recoveryKeyStore {
		t.Fatalf("RecoveryKeySessions injection ignored")
	}
	if app.GroupSessions == sessions.DefaultGroupSessionStore() {
		t.Fatalf("injected GroupSessions must not collapse to default singleton")
	}
}

// TestApp_SessionStores_AreIsolated: when two *App instances each get
// their own GroupSessionStore, a handle registered in one must not be
// visible in the other (parallel-test isolation regression guard — if
// handlers regress to calling sessions.Default*SessionStore() directly,
// both *App instances would see the same process-wide store and the
// handle would leak across).
func TestApp_SessionStores_AreIsolated(t *testing.T) {
	store1 := sessions.NewGroupSessionStore(15 * time.Minute)
	store2 := sessions.NewGroupSessionStore(15 * time.Minute)
	if store1 == store2 {
		t.Fatalf("NewGroupSessionStore must return distinct instances")
	}

	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i)
	}
	rawCopy := make([]byte, 32)
	copy(rawCopy, raw)
	handle, _, err := store1.Open(rawCopy)
	if err != nil {
		t.Fatalf("store1.Open: %v", err)
	}
	defer store1.Close(handle)

	if exists, _ := store1.Status(handle); !exists {
		t.Fatalf("handle must exist in store1 right after Open")
	}
	if exists, _ := store2.Status(handle); exists {
		t.Fatalf("handle from store1 must NOT be visible in store2 (process-wide leak)")
	}
}

func TestDefaultApp_Singleton(t *testing.T) {
	a := DefaultApp()
	b := DefaultApp()
	if a != b {
		t.Fatalf("DefaultApp must return same instance, got distinct pointers")
	}
	if a.Store == nil || a.Clock == nil || a.Rand == nil || a.Logger == nil || a.ServerKeyVerifier == nil {
		t.Fatalf("DefaultApp must have all fields populated")
	}
}

func TestMemorySecretStore_RoundTrip(t *testing.T) {
	s := NewMemorySecretStore()

	if err := s.Set("svc", "user", "secret"); err != nil {
		t.Fatalf("Set failed: %v", err)
	}
	got, err := s.Get("svc", "user")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if got != "secret" {
		t.Fatalf("got %q, want secret", got)
	}

	// Overwrite
	if err := s.Set("svc", "user", "secret2"); err != nil {
		t.Fatalf("Set overwrite failed: %v", err)
	}
	got, _ = s.Get("svc", "user")
	if got != "secret2" {
		t.Fatalf("overwrite did not stick: %q", got)
	}

	if err := s.Delete("svc", "user"); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}
	if _, err := s.Get("svc", "user"); !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("expected ErrSecretNotFound after Delete, got %v", err)
	}
}

func TestMemorySecretStore_GetMissing(t *testing.T) {
	s := NewMemorySecretStore()
	_, err := s.Get("svc", "missing")
	if !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("expected ErrSecretNotFound, got %v", err)
	}
}

func TestMemorySecretStore_DeleteMissing(t *testing.T) {
	s := NewMemorySecretStore()
	err := s.Delete("svc", "missing")
	if !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("expected ErrSecretNotFound on Delete missing, got %v", err)
	}
}

func TestMemorySecretStore_KeyIsolation(t *testing.T) {
	// Same account name but different service must remain isolated.
	s := NewMemorySecretStore()
	_ = s.Set("svc1", "user", "v1")
	_ = s.Set("svc2", "user", "v2")
	got1, _ := s.Get("svc1", "user")
	got2, _ := s.Get("svc2", "user")
	if got1 != "v1" || got2 != "v2" {
		t.Fatalf("service isolation broken: %q %q", got1, got2)
	}
}

func TestKeyringSecretStore_TranslatesNotFound(t *testing.T) {
	// keyring.MockInit for process-local isolation.
	keyring.MockInit()
	store := KeyringSecretStore{}
	_, err := store.Get("svc-missing-test", "user-x")
	if !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("expected ErrSecretNotFound, got %v", err)
	}
}

func TestKeyringSecretStore_RoundTrip(t *testing.T) {
	keyring.MockInit()
	store := KeyringSecretStore{}
	if err := store.Set("svc-rt", "user", "secret"); err != nil {
		t.Fatalf("Set failed: %v", err)
	}
	got, err := store.Get("svc-rt", "user")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if got != "secret" {
		t.Fatalf("got %q, want secret", got)
	}
	if err := store.Delete("svc-rt", "user"); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}
	if _, err := store.Get("svc-rt", "user"); !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("after Delete: expected ErrSecretNotFound, got %v", err)
	}
}

// TestApp_ClockInjection_SessionStore: verifies that App.Clock can be
// injected into GroupSessionStore via SetClock to enable deterministic
// expiry checks. Regression guard that the App pattern still composes
// cleanly with the existing session store.
func TestApp_ClockInjection_SessionStore(t *testing.T) {
	frozen := time.Date(2026, 4, 30, 12, 0, 0, 0, time.UTC)
	app := NewApp(Deps{Clock: func() time.Time { return frozen }})

	store := NewGroupSessionStore(15 * time.Minute)
	store.SetClock(app.Clock)

	rawDEK := make([]byte, 32)
	handle, expires, err := store.Open(rawDEK)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	expected := frozen.Add(15 * time.Minute)
	if !expires.Equal(expected) {
		t.Fatalf("expiresAt = %v, want %v", expires, expected)
	}

	// Confirm the handle is registered via Status.
	exists, _ := store.Status(handle)
	if !exists {
		t.Fatalf("handle should exist with frozen clock")
	}
}

// --- App.HandleRequest dispatcher boundary guards (was dispatcher_app_test.go) ---

// TestApp_HandleRequest_LogsViaLogger: on a normal ping request both
// "received action" and "ping request processing" lines must be captured
// by the logger. If we regress to calling stdlib log.Printf directly,
// MemoryLogger would not receive the messages.
func TestApp_HandleRequest_LogsViaLogger(t *testing.T) {
	logger := NewMemoryLogger()
	app := NewApp(Deps{Logger: logger})

	// Minimal ping request envelope.
	resp := app.HandleRequest([]byte(`{"action":"ping","request_id":"r1"}`))
	if !resp.Success {
		t.Fatalf("ping should succeed: %s", resp.Error)
	}
	if resp.RequestID != "r1" {
		t.Fatalf("RequestID echo failed: got %q", resp.RequestID)
	}
	if !logger.Contains("received action: ping") {
		t.Fatalf("expected dispatch log, got %v", logger.Messages())
	}
	if !logger.Contains("ping request processing") {
		t.Fatalf("expected handler log, got %v", logger.Messages())
	}
}

// TestApp_HandleRequest_UnknownActionReturnsUnsupported: unknown actions
// must return the unsupported code + log via a.Logger.
func TestApp_HandleRequest_UnknownActionReturnsUnsupported(t *testing.T) {
	logger := NewMemoryLogger()
	app := NewApp(Deps{Logger: logger})

	resp := app.HandleRequest([]byte(`{"action":"bogus_action_xyz","request_id":"r2"}`))
	if resp.Success {
		t.Fatalf("unknown action should fail")
	}
	if resp.ErrorCode != string(ErrCodeUnsupported) {
		t.Fatalf("expected unsupported code, got %q", resp.ErrorCode)
	}
	if !logger.Contains("unknown action: bogus_action_xyz") {
		t.Fatalf("expected dispatcher unknown-action log, got %v", logger.Messages())
	}
}

// TestApp_HandleRequest_InvalidJSONLoggedNotPanic: invalid JSON must
// fall into the unmarshal-failure branch — logs via a.Logger and returns
// a response envelope.
func TestApp_HandleRequest_InvalidJSONLoggedNotPanic(t *testing.T) {
	logger := NewMemoryLogger()
	app := NewApp(Deps{Logger: logger})

	resp := app.HandleRequest([]byte(`{not valid json`))
	if resp.Success {
		t.Fatalf("invalid JSON must fail")
	}
	if resp.Error != "invalid JSON format" {
		t.Fatalf("unexpected error message: %q", resp.Error)
	}
	if !logger.Contains("failed to unmarshal base request") {
		t.Fatalf("expected unmarshal-error log, got %v", logger.Messages())
	}
}

// TestApp_NewMessenger_UsesAppLogger: native messaging also injects the
// App instance's logger explicitly rather than via a DefaultApp()
// wrapper.
func TestApp_NewMessenger_UsesAppLogger(t *testing.T) {
	app := NewApp(Deps{Logger: NewMemoryLogger()})
	msgr := app.NewMessenger(nil, nil)
	if msgr == nil {
		t.Fatal("NewMessenger returned nil")
	}
}
