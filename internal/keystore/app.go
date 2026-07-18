// Package keystore — App + Deps: the single wiring point for the Keeper
// process.
//
// **Goal:** external reviewers see production wiring in one place. If a
// handler directly calls global dependencies like `time.Now()` /
// `crypto/rand.Reader` / `keyring.Get(...)`, you have to chase down "how
// is this mocked?". Putting SecretStore / Clock / Rand explicitly on
// App.Deps means:
//
//   - Unit tests can inject a fake store / fake clock / failing rand
//     easily.
//   - When new dependencies are added, adding a field to Deps preserves
//     structural visibility.
//   - main.go's production wiring stays short.
//
// Rand is also passed to handler-facing Deps so key material generation
// failure paths are testable. Low-level crypto helpers still use
// crypto/rand.Reader directly.
package keystore

import (
	"crypto/rand"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/dragpass/keeper/internal/keystore/clipboard"
	"github.com/dragpass/keeper/internal/keystore/sessions"
	"github.com/dragpass/keeper/internal/keystore/userpresence"
	"github.com/dragpass/keeper/internal/keystore/verifier"
)

// Clock is a function type that returns the current time.
//
// Kept as a type alias (not an interface) because:
//   - GroupSessionStore / RecoverySessionStore already use a
//     `now func() time.Time` field, so the coding style stays
//     consistent.
//   - Production wiring is a one-liner: `Clock(time.Now)` — Go-idiomatic.
//   - Wrapping it in an interface would force mocks to be
//     `func() time.Time { ... }` anyway, just with extra boilerplate.
type Clock = func() time.Time

// Deps bundles dependencies for production wiring + test injection.
//
// Every field is nil-tolerant — NewApp fills in production defaults for
// nil entries. Tests can inject partially by setting just the fields
// they care about.
type Deps struct {
	// Store is the OS Keychain abstraction. Defaults to
	// KeyringSecretStore if nil.
	Store SecretStore
	// Clock is the current-time source. Defaults to time.Now if nil.
	Clock Clock
	// Rand is the random source. Defaults to crypto/rand.Reader if nil.
	// Production paths must not use a deterministic reader (LGPL plan
	// §P1 random-source warning). Tests use it only to inject boundary
	// cases like a fail-on-N reader.
	Rand io.Reader
	// Logger is the structured-log sink. Defaults to StdLogger (delegates
	// to stdlib log) if nil.
	Logger Logger
	// ServerKeyVerifier verifies challenge_token signatures.
	// Defaults to DefaultServerKeyVerifier (wraps VerifyServerSig) if
	// nil.
	ServerKeyVerifier ServerKeyVerifier
	// GroupSessions is the in-memory store that protects raw Group DEKs
	// with memguard. Defaults to sessions.DefaultGroupSessionStore() — the
	// singleton main.go starts the reaper against. Tests inject an
	// isolated instance via sessions.NewGroupSessionStore(TTL).
	GroupSessions *sessions.GroupSessionStore
	// RecoverySessions is the store that protects restored OLD private
	// key PEM bytes with memguard. Defaults to
	// sessions.DefaultRecoverySessionStore() singleton if nil.
	RecoverySessions *sessions.RecoverySessionStore
	// RecoveryKeySessions protects short-lived RK24 values behind opaque
	// handles. Native Messaging carries only the handle.
	RecoveryKeySessions *sessions.RecoveryKeySessionStore
	// Clipboard is the OS-clipboard abstraction the decrypt-to-clipboard
	// actions write plaintext into. Defaults to the OS clipboard backend
	// if nil. On Init failure, Write fails explicitly.
	Clipboard clipboard.Clipboard
	// UserPresence is the trusted local UI boundary. Nil defaults to an
	// unavailable backend so callers cannot silently fall back to untrusted UI.
	UserPresence userpresence.UserPresence
}

// App is the single wiring container for the Keeper process. Handlers
// access dependencies through App rather than global state.
type App struct {
	Store               SecretStore
	Clock               Clock
	Rand                io.Reader
	Logger              Logger
	ServerKeyVerifier   ServerKeyVerifier
	GroupSessions       *sessions.GroupSessionStore
	RecoverySessions    *sessions.RecoverySessionStore
	RecoveryKeySessions *sessions.RecoveryKeySessionStore
	Clipboard           clipboard.Clipboard
	UserPresence        userpresence.UserPresence
}

// NewApp builds an App, filling in production defaults for nil fields in
// deps.
//
// Production wiring example:
//
//	app := keystore.NewApp(keystore.Deps{}) // all defaults
//
// Unit test example:
//
//	app := keystore.NewApp(keystore.Deps{
//	    Store: keystore.NewMemorySecretStore(),
//	    Clock: func() time.Time { return fakeNow },
//	})
func NewApp(deps Deps) *App {
	app := &App{
		Store:               deps.Store,
		Clock:               deps.Clock,
		Rand:                deps.Rand,
		Logger:              deps.Logger,
		ServerKeyVerifier:   deps.ServerKeyVerifier,
		GroupSessions:       deps.GroupSessions,
		RecoverySessions:    deps.RecoverySessions,
		RecoveryKeySessions: deps.RecoveryKeySessions,
		Clipboard:           deps.Clipboard,
		UserPresence:        deps.UserPresence,
	}
	if app.Store == nil {
		app.Store = KeyringSecretStore{}
	}
	if app.Clock == nil {
		app.Clock = time.Now
	}
	if app.Rand == nil {
		app.Rand = rand.Reader
	}
	if app.Logger == nil {
		app.Logger = StdLogger{}
	}
	if app.ServerKeyVerifier == nil {
		// DefaultServerKeyVerifier holds the SecretStore explicitly. The
		// app.Store fallback above runs first, so it's safe to delegate here.
		app.ServerKeyVerifier = verifier.NewDefaultServerKeyVerifier(app.Store)
	}
	if app.GroupSessions == nil {
		// Production fallback: the singleton that main.go starts the
		// reaper against.
		app.GroupSessions = sessions.DefaultGroupSessionStore()
	}
	if app.RecoverySessions == nil {
		app.RecoverySessions = sessions.DefaultRecoverySessionStore()
	}
	if app.RecoveryKeySessions == nil {
		app.RecoveryKeySessions = sessions.DefaultRecoveryKeySessionStore()
	}
	if app.Clipboard == nil {
		if testing.Testing() {
			// Test default — MemoryClipboard. Production OS clipboard would:
			//   - touch the developer's pasteboard on macOS local (state
			//     pollution + a real Init side effect),
			//   - return NoopClipboard with ErrUnavailable on headless Linux
			//     CI (asymmetric failure).
			// Tests that assert clipboard lifecycle should still inject a
			// MemoryClipboard via Deps explicitly so they can hold the
			// reference; this fallback only protects tests that never touch
			// the clipboard surface from accidental OS interaction.
			app.Clipboard = clipboard.NewMemoryClipboard()
		} else {
			// Production fallback: the OS clipboard
			// (golang.design/x/clipboard). If Init fails (e.g. a Wayland
			// surface is missing), NewProductionClipboard falls back
			// internally to NoopClipboard, but Write returns ErrUnavailable.
			app.Clipboard = clipboard.NewProductionClipboard()
		}
	}
	if app.UserPresence == nil {
		app.UserPresence = userpresence.Unavailable{}
	}
	return app
}

// defaultApp is the process-wide singleton — preserves the semantics of
// the legacy free functions (krSet, etc.) while letting new code use the
// App pattern. Guarded by sync.Once so it initializes exactly once on
// the first DefaultApp call.
var (
	defaultAppOnce sync.Once
	defaultApp     *App
	defaultDepsMu  sync.Mutex
	defaultDeps    Deps
)

// SetDefaultDeps pre-registers the Deps to use for DefaultApp's first
// sync.Once initialization.
//
// **When to call:** before the first DefaultApp() call. Used as a hook
// by main.go init() when it detects KEEPER_E2E_MODE, so e2e-only
// dependencies (MemoryClipboard, etc.) can be injected. Changes after
// the first DefaultApp() call are ignored and do not panic — the caller
// doesn't need to worry about races (production wiring calls init()
// exactly once).
func SetDefaultDeps(d Deps) {
	defaultDepsMu.Lock()
	defaultDeps = d
	defaultDepsMu.Unlock()
}

// DefaultApp returns the process singleton App. On first call,
// initializes via NewApp(<deps registered with SetDefaultDeps>). When no
// Deps are registered, NewApp(Deps{}) — all dependencies use production
// defaults.
//
// Tests should avoid this function and prefer NewApp for an isolated
// App.
func DefaultApp() *App {
	defaultAppOnce.Do(func() {
		defaultDepsMu.Lock()
		d := defaultDeps
		defaultDepsMu.Unlock()
		defaultApp = NewApp(d)
	})
	return defaultApp
}
