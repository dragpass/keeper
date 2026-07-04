// Package crypto — Crypto Service Boundary (LGPL P2).
//
// This file is a **doc-only file** with no function definitions. It serves as
// a one-page guide for both Go doc and LGPL public review, describing "where
// each crypto primitive lives and what its contract is."
//
// =====================================================================
// Crypto primitive map
// =====================================================================
//
// Each primitive lives in a small file with clear input/output/error
// conditions. Handlers (actions.go, *_actions.go) only call these and contain
// no crypto logic of their own. That is, handler == orchestration,
// primitive == this boundary.
//
// **AES-GCM** (`aes.go`)
//
//   - `AESGCMEncryptBase64(key, plaintext) (string, error)`
//   - input: 32B AES-256 key + plaintext bytes
//   - output: Base64( IV(12B) || ciphertext_with_tag )
//   - error: key length != 32 → "key must be 32 bytes (AES-256)"
//   - usage: Recovery Wrap (PEM ↔ wrap_key), Item DEK envelope, etc.
//   - `AESGCMDecryptBase64(key, b64) ([]byte, error)`
//   - input: 32B AES-256 key + Base64 envelope (same format as above)
//   - output: plaintext bytes
//   - error: key length / Base64 / IV length / GCM auth tag verification failure
//   - usage: Recovery Unwrap, Item DEK decrypt, etc.
//
// **RSA** (`keypair.go`)
//
//   - `GenerateRSAKeyPair() (*KeyPair, error)`
//   - output: 2048-bit PKCS#1 key pair PEM (`KeyPair.PrivateKey`, `.PublicKey`)
//   - usage: signup, user key rotation, Recovery new key generation.
//   - `ParsePrivateKey(pem string) (*rsa.PrivateKey, error)` /
//     `ParsePublicKey(pem string) (*rsa.PublicKey, error)` — PEM → struct.
//   - `SignData(priv, data) ([]byte, error)` — RSA-PSS-SHA256 (SaltLen=Hash).
//   - `VerifySignature(pub, data, sig) error` — verify with the same algorithm.
//   - `EncryptData(pub, plaintext) ([]byte, error)` — RSA-OAEP-SHA256.
//   - `DecryptData(priv, ciphertext) ([]byte, error)` — RSA-OAEP-SHA256.
//   - usage: Group DEK wrap/unwrap, challenge signing, Recovery signing.
//
// **Server signature verification** (`server_sig.go` + `server_key_verifier.go`)
//
//   - `VerifyServerSig(token, sigB64, version) error` — integrated helper.
//     PEM fetch (Keychain) + parse + Base64 decode + RSA-PSS-SHA256
//     verification. If version=0 falls back to active.
//   - `ServerKeyVerifier` interface — abstraction so that unit tests can stub
//     the verify behavior. `DefaultServerKeyVerifier` delegates in production.
//
// **Root signature verification** (`root_pubkey.go`)
//
//   - `VerifyServerKeyRootSignature(payload, sig) error` — root key verification
//     for Apocalypse scenarios. Separate from regular server operational key
//     rotation.
//   - `BuildServerKeyRootSigPayload(...)` — payload serialization (input for
//     root sig verification).
//   - `RootPublicKeyPEM()` — PEM embedded at build time via ldflags.
//
// =====================================================================
// Layered call graph
// =====================================================================
//
// handler (actions.go, *_actions.go)
//
//	↓
//
// orchestration: validation → crypto primitive → store → response envelope
//
//	↓
//	├── input validation (validation.go: requireBase64Len, etc.)
//	├── crypto primitive (aes.go / keypair.go / server_sig.go / root_pubkey.go)
//	├── storage (storage.go / server_keys.go → SecretStore via app.Store)
//	└── response envelope (errors.go: errorResponse / errorCodeResponse)
//
// Each layer is small and independent. The crypto primitive is stateless
// (no Keychain access — keys are taken as arguments). Key lookup is separated
// into the storage layer.
//
// =====================================================================
// Test policy (P2 plan §"Crypto Service Boundary")
// =====================================================================
//
// "Crypto function tests prefer real primitive round-trips over mocks."
//
// That is:
//
//   - AES-GCM: verify that seal → open round trip with the same key restores
//     the plaintext (use real crypto.aes, no mocks)
//   - RSA: actually run sign → verify or encrypt → decrypt round trip with
//     the same key pair
//   - server_sig: verify with real PEM + real signature
//   - tamper detection: flip one byte in the ciphertext or signature and
//     confirm rejection
//
// `crypto_roundtrip_test.go` locks in this policy as a worked example.
//
// Places where unit tests must use mocks:
//
//   - When handler unit tests want to stub only the verify step
//     (`AlwaysOKVerifier` / `AlwaysFailVerifier` from server_key_verifier.go)
//   - Regression guards for secret-exposure surfaces (`MemoryLogger`,
//     `MemorySecretStore`)
//
// These two cases verify "the orchestration that calls the primitive works
// via dependency injection," not "the primitive itself."
//
// =====================================================================
// Security guarantees
// =====================================================================
//
//  1. **Fixed algorithms**: AES-256-GCM (12B random IV), RSA-PSS-SHA256
//     (SaltLength=Hash), RSA-OAEP-SHA256. No algorithm negotiation — the
//     primitive caller cannot specify parameters.
//  2. **Constant-time comparison**: signature verification uses the standard
//     crypto/rsa package, so there is no timing leak.
//  3. **Random source**: all IVs / key pairs / nonces use `crypto/rand`. No
//     path in production allows a deterministic reader (Deps.Rand is
//     test-only).
//  4. **Memory lifecycle**: raw 32B keys / PEM bytes are wiped immediately
//     after use via `zeroize` or `memguard.LockedBuffer.Destroy`. See
//     the `secure.go` header for detailed guidance.
//
// =====================================================================
// Non-goals
// =====================================================================
//
//   - Adding new algorithms (e.g. ChaCha20-Poly1305, X25519). An algorithm
//     change is a wire format change and requires a phase-level change.
//   - Bundling everything into a giant "CryptoService" object. The P2 plan
//     explicitly recommends "keeping small files/functions per feature."
//   - Generic key wrap framework. Current wrap patterns are only (a)
//     RSA-OAEP-SHA256 for Group DEK / Item DEK / Recovery PEM envelopes
//     (b) AES-GCM for the Recovery wrap_key envelope — further generalization
//     is over-engineering.
package crypto
