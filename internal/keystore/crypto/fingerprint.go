package crypto

// fingerprint.go — the account key fingerprint and the MLS leaf key
// fingerprint.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
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

// MLSLeafSignatureKeyFingerprint returns lowercase hex(sha256(raw 32-byte
// Ed25519 public key)).
//
// Both fingerprints are a SHA-256 in hex, which is exactly why they must not
// share a function: the account one hashes whatever PEM it is handed, so a leaf
// key routed through it would hash an encoding and still produce a
// well-formed, wrong answer. Refusing any input that is not a raw key is what
// makes that mistake fail instead.
func MLSLeafSignatureKeyFingerprint(publicKey ed25519.PublicKey) (string, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return "", errors.New("mls leaf signature key must be a raw 32-byte Ed25519 public key")
	}
	sum := sha256.Sum256(publicKey)
	return hex.EncodeToString(sum[:]), nil
}
