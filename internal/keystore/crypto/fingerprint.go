package crypto

// fingerprint.go — the account key fingerprint.

import (
	"crypto/sha256"
	"encoding/hex"
)

// AccountKeyFingerprint returns lowercase hex(sha256(pem bytes)) — the one
// fingerprint formula the account key trust model uses.
//
// The input is the public key PEM exactly as it arrived. Nothing is trimmed,
// re-wrapped, or re-encoded first: the Extension, the server, and the Keeper
// each hash the same bytes, and a single added newline would split the three
// results without anything failing loudly. The server stores that PEM Base64
// encoded, so its input is the decode of `accounts.public_key`; the Keeper
// already holds the PEM and has nothing to decode.
//
// This is deliberately not the formula behind `account_device_keys`'s
// fingerprint, which hashes the Base64 *string*. That one stays an internal
// identifier and never names an account key.
func AccountKeyFingerprint(publicKeyPEM []byte) string {
	sum := sha256.Sum256(publicKeyPEM)
	return hex.EncodeToString(sum[:])
}
