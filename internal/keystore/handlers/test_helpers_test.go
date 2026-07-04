// test_helpers_test.go — shared helpers for handlers-package unit tests.
//
// Unit tests call `handlers.HandleX(deps, req)` free-function form directly
// (no `NewApp(Deps{...})` + `app.HandleX(req)` wrapping). This file exposes
// only two helpers:
//
//   - newTestDeps(t)             → MemoryLogger + MemorySecretStore + AlwaysOKVerifier
//   - isolated GroupSessionStore + RecoverySessionStore
//   - newTestDepsFailVerify(t,e) → same as above, but ServerKeyVerifier rejects with e
//
// Both return fresh instances per call, so parallel unit tests are safe —
// session stores also create a new store each time instead of a process-wide
// singleton, preventing handles registered by other tests from leaking in.
package handlers

import (
	"testing"

	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/logger"
	"github.com/dragpass/keeper/internal/keystore/sessions"
	"github.com/dragpass/keeper/internal/keystore/verifier"
)

// newTestDeps creates an isolated Deps with MemoryLogger + MemorySecretStore +
// AlwaysOKVerifier + fresh session stores. Each call returns fresh instances so
// tests don't bleed.
func newTestDeps(t *testing.T) (Deps, *logger.MemoryLogger, *keychain.MemorySecretStore) {
	t.Helper()
	log := logger.NewMemoryLogger()
	store := keychain.NewMemorySecretStore()
	return Deps{
		Logger:            log,
		Store:             store,
		ServerKeyVerifier: verifier.AlwaysOKVerifier{},
		GroupSessions:     sessions.NewGroupSessionStore(sessions.GroupSessionTTL),
		RecoverySessions:  sessions.NewRecoverySessionStore(sessions.RecoverySessionTTL),
	}, log, store
}

// newTestDepsFailVerify is like newTestDeps but the verifier rejects everything.
func newTestDepsFailVerify(t *testing.T, err error) (Deps, *logger.MemoryLogger, *keychain.MemorySecretStore) {
	t.Helper()
	deps, log, store := newTestDeps(t)
	deps.ServerKeyVerifier = verifier.AlwaysFailVerifier{Err: err}
	return deps, log, store
}
