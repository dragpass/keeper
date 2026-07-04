package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
)

// AESGCMEncryptBase64 encrypts plaintext with AES-GCM using a 256-bit key,
// prepends a freshly generated 12-byte IV to the ciphertext, and returns
// the result as Base64.
//
// Output format: Base64( IV(12B) || ciphertext_with_tag )
//
// Used in Recovery Wrap when wrapping a new Keeper private key PEM with an
// AES-GCM key derived from the wrap branch of RK24. The key length is fixed
// at 32 bytes.
func AESGCMEncryptBase64(key, plaintext []byte) (string, error) {
	if len(key) != 32 {
		return "", errors.New("key must be 32 bytes (AES-256)")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	iv := make([]byte, gcm.NonceSize()) // 12 bytes
	if _, err := rand.Read(iv); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nil, iv, plaintext, nil)

	out := make([]byte, 0, len(iv)+len(ciphertext))
	out = append(out, iv...)
	out = append(out, ciphertext...)

	return base64.StdEncoding.EncodeToString(out), nil
}

// AESGCMDecryptBase64 reverses AESGCMEncryptBase64. Currently unused inside
// Keeper (Recovery decrypts the wrapped keeper on the Extension side via Web
// Crypto), but kept symmetric for testing and potential future use.
func AESGCMDecryptBase64(key []byte, b64 string) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("key must be 32 bytes (AES-256)")
	}

	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(raw) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}

	iv := raw[:gcm.NonceSize()]
	ciphertext := raw[gcm.NonceSize():]

	return gcm.Open(nil, iv, ciphertext, nil)
}
