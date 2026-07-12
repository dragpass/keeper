// secure_bridge.go — secure helpers that depend on Keychain access + crypto.
//
// Pure memory-hygiene helpers (zeroize / wipeString / withDecodedSecretB64,
// etc.) live in the internal/keystore/secure/ subpackage. The functions left
// in this file depend on Keychain access + crypto primitives, so they were
// moved into the handlers package (previously the keystore root).

package handlers

import (
	"crypto/rsa"
	"encoding/base64"

	"github.com/awnumar/memguard"

	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/secure"
)

// GetPrivateKeySecure retrieves the private key from keychain,
// copies it into a memguard LockedBuffer, and wipes the original Go string copy.
// Caller MUST call buf.Destroy() when done.
//
// Exported (with the lowercase alias `getPrivateKeySecure` in this package)
// so keystore root tests can drive the bridge directly.
func GetPrivateKeySecure(store keychain.SecretStore) (*memguard.LockedBuffer, error) {
	pemStr, err := keychain.GetPrivateKey(store)
	if err != nil {
		return nil, err
	}

	buf := memguard.NewBufferFromBytes([]byte(pemStr))
	// Overwrite the Go string's backing byte slice as best-effort
	secure.WipeString(&pemStr)

	return buf, nil
}

// GetPendingPrivateKeySecure is the same as GetPrivateKeySecure but for pending keys.
func GetPendingPrivateKeySecure(store keychain.SecretStore) (*memguard.LockedBuffer, error) {
	pemStr, err := keychain.GetPendingPrivateKey(store)
	if err != nil {
		return nil, err
	}

	buf := memguard.NewBufferFromBytes([]byte(pemStr))
	secure.WipeString(&pemStr)

	return buf, nil
}

// GetArchivePrivateKeySecure is the same as GetPrivateKeySecure but for the
// per-org archive private key slot. Returns keychain.ErrSecretNotFound (→
// not_found) when the archive slot is empty.
func GetArchivePrivateKeySecure(store keychain.SecretStore) (*memguard.LockedBuffer, error) {
	pemStr, err := keychain.GetArchivePrivateKey(store)
	if err != nil {
		return nil, err
	}

	buf := memguard.NewBufferFromBytes([]byte(pemStr))
	secure.WipeString(&pemStr)

	return buf, nil
}

// GetAccountArchivePrivateKeySecure is the same as GetArchivePrivateKeySecure
// but for the per-account archive receiving-key slot. Returns
// keychain.ErrSecretNotFound (→ not_found) when the account slot is empty.
func GetAccountArchivePrivateKeySecure(store keychain.SecretStore) (*memguard.LockedBuffer, error) {
	pemStr, err := keychain.GetAccountArchivePrivateKey(store)
	if err != nil {
		return nil, err
	}

	buf := memguard.NewBufferFromBytes([]byte(pemStr))
	secure.WipeString(&pemStr)

	return buf, nil
}

// GetArchiveSessionPrivateKeySecure is the same as GetArchivePrivateKeySecure
// but for the archive quorum recovery-session ephemeral slot. Returns
// keychain.ErrSecretNotFound (→ not_found) when no session is open.
func GetArchiveSessionPrivateKeySecure(store keychain.SecretStore) (*memguard.LockedBuffer, error) {
	pemStr, err := keychain.GetArchiveSessionPrivateKey(store)
	if err != nil {
		return nil, err
	}

	buf := memguard.NewBufferFromBytes([]byte(pemStr))
	secure.WipeString(&pemStr)

	return buf, nil
}

// ParsePrivateKeyFromSecureBuf parses an RSA private key from a LockedBuffer.
// The LockedBuffer is NOT destroyed here — caller controls lifetime.
func ParsePrivateKeyFromSecureBuf(buf *memguard.LockedBuffer) (*rsa.PrivateKey, error) {
	return crypto.ParsePrivateKey(string(buf.Bytes()))
}

// DecryptToSecureBuf decrypts data and returns the plaintext in a LockedBuffer.
// The raw decrypted bytes are wiped immediately after copying into protected memory.
func DecryptToSecureBuf(privateKey *rsa.PrivateKey, encryptedData []byte) (*memguard.LockedBuffer, error) {
	plainBytes, err := crypto.DecryptData(privateKey, encryptedData)
	if err != nil {
		return nil, err
	}

	buf := memguard.NewBufferFromBytes(plainBytes)
	secure.Zeroize(plainBytes)

	return buf, nil
}

// SignDataSecure signs data using a private key from a LockedBuffer.
// Returns base64-encoded signature.
func SignDataSecure(privKeyBuf *memguard.LockedBuffer, data string) (string, error) {
	privateKey, err := ParsePrivateKeyFromSecureBuf(privKeyBuf)
	if err != nil {
		return "", err
	}

	sigBytes, err := crypto.SignData(privateKey, data)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(sigBytes), nil
}

// ────────────────────────────────────────────────────────────────────────
// Lowercase aliases — handlers/ package internals.
//
// Other handler files that import this file call these via shorter names.
// ────────────────────────────────────────────────────────────────────────

func getPrivateKeySecure(store keychain.SecretStore) (*memguard.LockedBuffer, error) {
	return GetPrivateKeySecure(store)
}

func getPendingPrivateKeySecure(store keychain.SecretStore) (*memguard.LockedBuffer, error) {
	return GetPendingPrivateKeySecure(store)
}

func parsePrivateKeyFromSecureBuf(buf *memguard.LockedBuffer) (*rsa.PrivateKey, error) {
	return ParsePrivateKeyFromSecureBuf(buf)
}

func decryptToSecureBuf(privateKey *rsa.PrivateKey, encryptedData []byte) (*memguard.LockedBuffer, error) {
	return DecryptToSecureBuf(privateKey, encryptedData)
}

func signDataSecure(privKeyBuf *memguard.LockedBuffer, data string) (string, error) {
	return SignDataSecure(privKeyBuf, data)
}
