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
	"github.com/dragpass/keeper/internal/keystore/keytransparency"
	"github.com/dragpass/keeper/internal/keystore/logger"
	"github.com/dragpass/keeper/internal/keystore/sessions"
	"github.com/dragpass/keeper/internal/keystore/verifier"
)

// Deps is the minimal contract handlers depend on. App wraps its own fields
// in this struct and passes it along the dispatcher path.
//
// Session stores are injected so App owns their lifetime and tests remain
// isolated.
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
	// MessageChallenges is the process-local challenge map behind the two-step
	// secure-message reveal (message_display_prepare →
	// group_decrypt_with_aad_for_app_display). Injected like the session stores
	// so App owns its lifetime and parallel tests do not share entries. A nil
	// store fails closed: no challenge can be minted and none can be consumed.
	MessageChallenges *MessageChallengeStore
	// GroupDisplayChallenges binds a one-use online Group display decision to
	// the local handle and frame. Nil fails closed until the action is wired.
	GroupDisplayChallenges *GroupDisplayChallengeStore
	// ChangeBaselineChallenges binds a one-use change-baseline decision (lv83)
	// to the exact token and entry Keeper prepared. A separate store, so a
	// baseline challenge can never satisfy a display decision or the reverse.
	ChangeBaselineChallenges *GroupDisplayChallengeStore
	// ChangeCompareChallenges binds a one-use comparison decision (lv83 H1)
	// to the handle, entry and record Keeper prepared.
	ChangeCompareChallenges *GroupDisplayChallengeStore
	// CredentialNonces is the process-local single-use record behind the
	// credential sinks (credential_execution_prepare → credential_http_request /
	// credential_exec_request). A nil store fails closed.
	CredentialNonces *CredentialNonceStore
	// AuditAuthorizations is the process-local single-use record of the audit
	// actions' receipts and permits. A nil store fails closed.
	AuditAuthorizations *AuditAuthorizationStore
	KeyTransparency     keytransparency.Gate
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
