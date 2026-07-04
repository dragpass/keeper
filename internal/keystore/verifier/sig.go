// Package verifier — Server signature verification.
//
// Extracted into a dedicated subpackage: the "verify challenge signature
// using a key identified by server_key_version" helper and its abstraction
// (`ServerKeyVerifier` interface), separated from the keystore root.
// Previous location: `internal/keystore/server_sig.go` +
// `internal/keystore/server_key_verifier.go`.
//
// **Why separated (§"verifier boundary"):**
//
//   - Server signature verification is a hot path called by 8+ handlers
//     (Recovery, Rotation, Login, server-key-version pass-through, etc.).
//   - Verification is a 4-step mix of stateful Keychain lookup and crypto
//     primitives: (a) PEM lookup in Keychain (b) PEM parse (c) Base64 decode
//     (d) RSA-PSS verify — naturally a distinct "verify surface" boundary.
//   - Leaving it in the keystore root mixes it with `*App` methods + free
//     function wrappers, making it hard for reviewers to focus on the verify
//     contract alone.
//
// **External impact:** keystore root's `verifier_aliases.go` exposes this
// package's types/functions as aliases, so existing call sites
// (`a.ServerKeyVerifier.Verify(...)`, `keystore.AlwaysOKVerifier{}`,
// `keystore.VerifyServerSig(...)`) are unchanged.
//
// Signature change: `VerifyServerSig` now takes `keychain.SecretStore` as
// the first argument (previously the `getServerPublicKeyForVersion` free
// function delegated through `DefaultApp().Store`). The verifier package now
// declares its SecretStore dependency explicitly.

package verifier

import (
	"encoding/base64"
	"fmt"

	"github.com/golang-jwt/jwt/v4"

	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/keychain"
)

// VerifyServerSig verifies that sigB64 is a valid signature over token using
// the server public key identified by server_key_version. version=0 falls
// back to active.
//
// This helper bundles four steps into a single call:
//  1. Look up the versioned public key PEM in the SecretStore
//  2. Parse the PEM (RSA public key)
//  3. Base64-decode the signature
//  4. RSA-PSS verify
//
// Error message prefixes are preserved so regression guards /
// withServerKeyRefreshFallback regex / unit tests can identify them:
//   - "failed to get server public key: <inner>"
//   - "failed to parse server public key: <inner>"
//   - "failed to decode signature: <inner>"
//   - "server signature verification failed: <inner>"
//
// Wrapped via %w so errors.Is/As can inspect the inner error.
func VerifyServerSig(store keychain.SecretStore, token string, sigB64 string, serverKeyVersion uint) error {
	pem, err := keychain.GetServerPublicKeyForVersion(store, serverKeyVersion)
	if err != nil {
		return fmt.Errorf("failed to get server public key: %w", err)
	}
	pub, err := jwt.ParseRSAPublicKeyFromPEM([]byte(pem))
	if err != nil {
		return fmt.Errorf("failed to parse server public key: %w", err)
	}
	sigBytes, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}
	if err := crypto.VerifySignature(pub, token, sigBytes); err != nil {
		return fmt.Errorf("server signature verification failed: %w", err)
	}
	return nil
}
