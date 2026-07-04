// verifier.go — ServerKeyVerifier interface + production/test impls.
//
// **DI motivation:** challenge_token + signature verification is a hot path
// called by 8+ handlers (Recovery, Rotation, Login, server-key-version
// pass-through). Today the free function `VerifyServerSig` (a unified helper)
// handles stateful Keychain lookup + RSA-PSS verification in one call.
//
// Splitting it into the ServerKeyVerifier interface lets:
//
//   - Unit tests stub the verify behavior without seeding a PEM Keychain.
//   - active/deprecated/grace-period server-key policy be encapsulated in
//     the verifier implementation — handlers see only the "verify result".
//   - Future root-signature verification (Apocalypse scenario) extend the
//     same interface.

package verifier

import (
	"errors"

	"github.com/dragpass/keeper/internal/keystore/keychain"
)

// ServerKeyVerifier is the contract for verifying a signature over a
// challenge_token using a server public key. server_key_version=0 falls
// back to the active key.
//
// Return errors:
//   - nil: verification succeeded
//   - non-nil: failure in one of the steps (key lookup / parse / decode /
//     RSA-PSS verify). Preserves the existing VerifyServerSig error prefixes
//     ("failed to get server public key:" / "server signature verification
//     failed:" etc.) so external regression patterns do not break.
type ServerKeyVerifier interface {
	Verify(token string, sigB64 string, serverKeyVersion uint) error
}

// DefaultServerKeyVerifier is the production verifier — delegates to the
// `VerifyServerSig` free function with the SecretStore.
//
// Holds a Store field. It was previously a stateless struct and
// `VerifyServerSig` delegated automatically through `DefaultApp().Store`.
// Making the SecretStore dependency explicit removes the verifier package's
// dependency on the keystore root's App singleton — inject via
// `NewDefaultServerKeyVerifier(store)`.
type DefaultServerKeyVerifier struct {
	Store keychain.SecretStore
}

// NewDefaultServerKeyVerifier builds a production verifier that encapsulates
// the SecretStore. Production wiring is one line:
// `NewDefaultServerKeyVerifier(deps.Store)`.
func NewDefaultServerKeyVerifier(store keychain.SecretStore) DefaultServerKeyVerifier {
	return DefaultServerKeyVerifier{Store: store}
}

func (v DefaultServerKeyVerifier) Verify(token string, sigB64 string, serverKeyVersion uint) error {
	return VerifyServerSig(v.Store, token, sigB64, serverKeyVersion)
}

// AlwaysOKVerifier is a unit-test stub — returns nil for every input.
// Use it to pass through the handler's verify step and assert on the next
// flow.
type AlwaysOKVerifier struct{}

func (AlwaysOKVerifier) Verify(token string, sigB64 string, serverKeyVersion uint) error {
	return nil
}

// AlwaysFailVerifier is a unit-test stub — returns the same error for every
// input. Use it to assert "what does the handler do when verify fails".
type AlwaysFailVerifier struct {
	Err error
}

func (v AlwaysFailVerifier) Verify(token string, sigB64 string, serverKeyVersion uint) error {
	if v.Err == nil {
		return errors.New("server signature verification failed: stub")
	}
	return v.Err
}
