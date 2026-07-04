// Verifier aliases.
//
// Handlers, app.go, dispatcher, and tests reference these names without the
// `verifier.` prefix; the actual implementation lives in
// internal/keystore/verifier/. Code reaches the verifier via
// `App.ServerKeyVerifier` or by calling the package directly.

package keystore

import "github.com/dragpass/keeper/internal/keystore/verifier"

type (
	ServerKeyVerifier        = verifier.ServerKeyVerifier
	DefaultServerKeyVerifier = verifier.DefaultServerKeyVerifier
	AlwaysOKVerifier         = verifier.AlwaysOKVerifier
)
