// Package anchor — The Root public key embedded in Keeper and verification
// utilities.
//
// **Trust model**: the Root public key is embedded in the Keeper binary at
// build time. All subsequently issued operational server public keys are
// signed with the Root private key and delivered via the
// `GET /api/v1/system/server-keys` response. Keeper verifies the signature
// with the Root public key before storing them in the Keychain.
//
// **Embedding methods**:
//   - Production: at build time inject
//     `-ldflags "-X github.com/.../keystore/anchor.rootPublicKeyPEMBase64=<base64>"`
//   - Development: fall back to the `KEEPER_ROOT_PUBLIC_KEY_BASE64` env var
//   - If both are empty, RootMissing mode (skip signature verification,
//     fingerprint TOFU pin) — a safety net for compatibility and gradual
//     rollout.
//
// **Fingerprint format**: `"sha256:" + hex(sha256(pemBytes))`. The server
// hashes the same input with the same function — any format drift causes a
// silent reject.
//
// **Payload format**: 1:1 compatible with `ComputeServerKeyRootSigPayload`.
//
//	"v1|<version>|<public_pem>|<issued_unix>|<expires_unix>"
//
// The server produces this format and Keeper hashes the same format for
// RSA-PSS-SHA256 verification.
//
// Split out of internal/keystore root. Callers (refresh_server_keys.go) see
// the same names via var aliases in internal/keystore/anchor_aliases.go.
package anchor

import (
	stdcrypto "crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"

	"github.com/golang-jwt/jwt/v4"
	keepercrypto "github.com/dragpass/keeper/internal/keystore/crypto"
)

// rootPublicKeyPEMBase64 is the Base64 of the Root pubkey PEM injected at
// build time via -ldflags. If empty, falls back to the
// KEEPER_ROOT_PUBLIC_KEY_BASE64 env var. If that is also empty, RootMissing
// mode.
//
// **ldflags injection path**:
//
//	-X github.com/dragpass/keeper/internal/keystore/anchor.rootPublicKeyPEMBase64=<base64>
var rootPublicKeyPEMBase64 string

// ErrRootKeyNotConfigured is returned when the Root public key is not
// embedded and not set in the env var.
var ErrRootKeyNotConfigured = errors.New("root server public key not configured (build without -ldflags or KEEPER_ROOT_PUBLIC_KEY_BASE64 not set)")

// RootPublicKeyPEM returns the Root pubkey PEM string using
// embedded/env priority. If neither is set, returns an empty string
// (the caller branches).
func RootPublicKeyPEM() (string, error) {
	source := rootPublicKeyPEMBase64
	if source == "" {
		source = os.Getenv("KEEPER_ROOT_PUBLIC_KEY_BASE64")
	}
	if source == "" {
		return "", nil
	}
	pemBytes, err := base64.StdEncoding.DecodeString(source)
	if err != nil {
		return "", fmt.Errorf("decode root pubkey base64: %w", err)
	}
	return string(pemBytes), nil
}

// ComputeRootKeyFingerprint returns the fingerprint of the embedded Root
// pubkey. Same algorithm as the server-side hash.ComputeRootKeyFingerprint:
//
//	"sha256:" + hex(sha256(pem_bytes))
//
// If the Root is not embedded, returns ErrRootKeyNotConfigured.
func ComputeRootKeyFingerprint() (string, error) {
	pem, err := RootPublicKeyPEM()
	if err != nil {
		return "", err
	}
	if pem == "" {
		return "", ErrRootKeyNotConfigured
	}
	h := sha256.Sum256([]byte(pem))
	return "sha256:" + hex.EncodeToString(h[:]), nil
}

// VerifyServerKeyRootSignature verifies the root_signature of a single
// server_keys response entry with the embedded Root pubkey.
//
// payload is produced via
// `BuildServerKeyRootSigPayload(version, pem, issuedUnix, expiresUnix)`.
// signature is RSA-PSS SHA-256.
//
// If the Root is not embedded, returns ErrRootKeyNotConfigured — the caller
// branches into RootMissing mode.
func VerifyServerKeyRootSignature(payload []byte, signature []byte) error {
	pem, err := RootPublicKeyPEM()
	if err != nil {
		return err
	}
	if pem == "" {
		return ErrRootKeyNotConfigured
	}
	pubKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(pem))
	if err != nil {
		return fmt.Errorf("parse root public key PEM: %w", err)
	}
	hashed := sha256.Sum256(payload)
	if err := rsa.VerifyPSS(pubKey, stdcrypto.SHA256, hashed[:], signature, keepercrypto.RSAPSSOptions()); err != nil {
		return fmt.Errorf("root signature verification failed: %w", err)
	}
	return nil
}

// BuildServerKeyRootSigPayload produces the canonical payload that the
// server signs ("v1|..."). Both sides must produce the same byte sequence
// from the same input for verification to pass.
//
// Form: "v1|<version>|<public_pem>|<issued_unix>|<expires_unix>"
//
//   - issuedUnix/expiresUnix are Unix epoch seconds (int64).
//   - Whether public_pem has a trailing newline must match exactly (the
//     server uses the PEM string verbatim).
func BuildServerKeyRootSigPayload(version uint, publicPEM string, issuedUnix, expiresUnix int64) []byte {
	return fmt.Appendf(nil,
		"v1|%d|%s|%d|%d",
		version,
		publicPEM,
		issuedUnix,
		expiresUnix,
	)
}
