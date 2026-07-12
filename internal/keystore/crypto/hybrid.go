// hybrid.go — RSA-OAEP + AES-GCM hybrid wrap for payloads larger than the
// RSA-OAEP plaintext limit.
//
// A 2048-bit RSA-OAEP-SHA256 wrap can carry at most 190 bytes, but a Shamir
// share of the ~1.7 KB archive private-key PEM is far larger. HybridWrap
// generates a fresh 32-byte AES-256 key, AES-GCM-encrypts the payload under it,
// and RSA-OAEP-wraps only that key to the recipient. The recipient reverses it
// with their RSA private key. This is the same envelope shape used elsewhere
// for large-secret transport, kept in one helper so the two quorum actions and
// their tests agree on the format.

package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
)

// HybridWrap encrypts plaintext to pub.
//
//	wrappedKeyB64: Base64( RSA-OAEP-SHA256( 32-byte AES key ) )
//	ciphertextB64: Base64( IV(12) || AES-256-GCM(plaintext) )  (AESGCMEncryptBase64 format)
func HybridWrap(pub *rsa.PublicKey, plaintext []byte) (wrappedKeyB64, ciphertextB64 string, err error) {
	aesKey := make([]byte, 32)
	if _, err = rand.Read(aesKey); err != nil {
		return "", "", fmt.Errorf("hybrid wrap: rand key: %w", err)
	}
	defer zeroize(aesKey)

	ciphertextB64, err = AESGCMEncryptBase64(aesKey, plaintext)
	if err != nil {
		return "", "", fmt.Errorf("hybrid wrap: aes-gcm: %w", err)
	}

	wrappedKey, err := EncryptData(pub, aesKey)
	if err != nil {
		return "", "", fmt.Errorf("hybrid wrap: rsa-oaep key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(wrappedKey), ciphertextB64, nil
}

// HybridUnwrap reverses HybridWrap with the recipient's RSA private key.
func HybridUnwrap(priv *rsa.PrivateKey, wrappedKeyB64, ciphertextB64 string) ([]byte, error) {
	wrappedKey, err := base64.StdEncoding.DecodeString(wrappedKeyB64)
	if err != nil {
		return nil, fmt.Errorf("hybrid unwrap: decode wrapped key: %w", err)
	}
	aesKey, err := DecryptData(priv, wrappedKey)
	if err != nil {
		return nil, fmt.Errorf("hybrid unwrap: rsa-oaep key: %w", err)
	}
	defer zeroize(aesKey)

	plaintext, err := AESGCMDecryptBase64(aesKey, ciphertextB64)
	if err != nil {
		return nil, fmt.Errorf("hybrid unwrap: aes-gcm: %w", err)
	}
	return plaintext, nil
}

// zeroize overwrites a byte slice. A local copy of the secure package's helper
// to avoid an import cycle (secure imports crypto).
func zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
