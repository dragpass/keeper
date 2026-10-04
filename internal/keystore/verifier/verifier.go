// Server signature verification boundary.

package verifier

import "github.com/dragpass/keeper/internal/keystore/keychain"

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

// DefaultServerKeyVerifier reads versioned keys from the secret store.
type DefaultServerKeyVerifier struct {
	Store keychain.SecretStore
}

func NewDefaultServerKeyVerifier(store keychain.SecretStore) DefaultServerKeyVerifier {
	return DefaultServerKeyVerifier{Store: store}
}

func (v DefaultServerKeyVerifier) Verify(token string, sigB64 string, serverKeyVersion uint) error {
	return VerifyServerSig(v.Store, token, sigB64, serverKeyVersion)
}
