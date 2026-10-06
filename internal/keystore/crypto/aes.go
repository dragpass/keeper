package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"io"
)

// SealAESGCM encrypts plaintext with AES-256-GCM under a fresh 12-byte IV read
// from random, binding aad (nil for none) into the tag. It is Keeper's one
// AES-GCM seal; handlers pass Deps.Random() so the IV source is injectable.
func SealAESGCM(random io.Reader, key, plaintext, aad []byte) (iv, ciphertext []byte, err error) {
	gcm, err := newAESGCM(key)
	if err != nil {
		return nil, nil, err
	}
	iv = make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(random, iv); err != nil {
		return nil, nil, err
	}
	return iv, gcm.Seal(nil, iv, plaintext, aad), nil
}

// OpenAESGCM reverses SealAESGCM. Opening fails unless aad is byte-identical
// to the aad the seal bound.
func OpenAESGCM(key, iv, ciphertext, aad []byte) ([]byte, error) {
	gcm, err := newAESGCM(key)
	if err != nil {
		return nil, err
	}
	if len(iv) != gcm.NonceSize() {
		return nil, errors.New("iv length mismatch")
	}
	return gcm.Open(nil, iv, ciphertext, aad)
}

// AESGCMEncryptBase64 is SealAESGCM without AAD, returned as
// Base64(IV(12B) || ciphertext_with_tag): the form of the device-wrapped DEK
// and of the RK24 recovery wrap of the account private key PEM.
func AESGCMEncryptBase64(random io.Reader, key, plaintext []byte) (string, error) {
	iv, ciphertext, err := SealAESGCM(random, key, plaintext, nil)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(append(iv, ciphertext...)), nil
}

// AESGCMDecryptBase64 reverses AESGCMEncryptBase64.
func AESGCMDecryptBase64(key []byte, b64 string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}
	if len(raw) < 12 {
		return nil, errors.New("ciphertext too short")
	}
	return OpenAESGCM(key, raw[:12], raw[12:], nil)
}

func newAESGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, errors.New("key must be 32 bytes (AES-256)")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
