// Package handlers — request handler implementations.
//
// Handlers are free functions that take a Deps struct instead of being *App
// methods. The App struct remains the keystore root. The dispatcher builds a
// Deps via app.HandlersDeps() and passes it to handlers.
//
// An LGPL reviewer can verify "which dependency is injected into which
// handler" in one place.
package handlers

import (
	cryptorand "crypto/rand"
	"io"
	"time"

	"github.com/dragpass/keeper/internal/keystore/clipboard"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/logger"
	"github.com/dragpass/keeper/internal/keystore/sessions"
	"github.com/dragpass/keeper/internal/keystore/userpresence"
	"github.com/dragpass/keeper/internal/keystore/verifier"
)

// Deps is the minimal contract handlers depend on. App wraps its own fields
// in this struct and passes it along the dispatcher path.
//
// **Session stores:** GroupSessions / RecoverySessions are handles to in-memory
// session stores that protect raw Group DEK / recovery PEM with memguard. If
// handlers called the `sessions.Default*SessionStore()` singleton directly,
// parallel unit tests would share process-wide state and interfere with each
// other, so this is injected explicitly. Production wiring has NewApp fill in
// the default singleton; tests inject isolated instances via
// `sessions.NewGroupSessionStore(TTL)` / `NewRecoverySessionStore(TTL)`.
type Deps struct {
	Logger              logger.Logger
	Store               keychain.SecretStore
	Clock               func() time.Time
	Rand                io.Reader
	ServerKeyVerifier   verifier.ServerKeyVerifier
	GroupSessions       *sessions.GroupSessionStore
	RecoverySessions    *sessions.RecoverySessionStore
	RecoveryKeySessions *sessions.RecoveryKeySessionStore
	// Clipboard is the OS clipboard abstraction that the decrypt-to-clipboard
	// action writes plaintext to. If nil, writeClipboard fails. Production App
	// fills in the OS clipboard backend; unit tests inject an isolated
	// MemoryClipboard instance.
	Clipboard clipboard.Clipboard
	// UserPresence owns trusted OS prompts. Production defaults to a
	// fail-closed unavailable backend until a platform implementation is wired.
	UserPresence userpresence.UserPresence
}

func (d Deps) Now() time.Time {
	if d.Clock != nil {
		return d.Clock()
	}
	return time.Now()
}

func (d Deps) Random() io.Reader {
	if d.Rand != nil {
		return d.Rand
	}
	return cryptorand.Reader
}

func (d Deps) FillRandom(dst []byte) error {
	_, err := io.ReadFull(d.Random(), dst)
	return err
}
