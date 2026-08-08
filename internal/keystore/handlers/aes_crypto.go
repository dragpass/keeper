// Shared AES-GCM helpers.

package handlers

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
)

// AESGCMSeal takes raw key + plaintext and returns Base64(IV(12) || ciphertext_with_tag).
func AESGCMSeal(key, plaintext []byte) (string, error) {
	iv, ciphertext, err := aesGCMSealSplit(key, plaintext)
	if err != nil {
		return "", err
	}
	out := make([]byte, 0, len(iv)+len(ciphertext))
	out = append(out, iv...)
	out = append(out, ciphertext...)
	return base64.StdEncoding.EncodeToString(out), nil
}

// AESGCMSealSplit returns IV and ciphertext_with_tag separately.
func AESGCMSealSplit(key, plaintext []byte) ([]byte, []byte, error) {
	if len(key) != 32 {
		return nil, nil, errors.New("key must be 32 bytes (AES-256)")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	iv := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(iv); err != nil {
		return nil, nil, err
	}
	ciphertext := gcm.Seal(nil, iv, plaintext, nil)
	return iv, ciphertext, nil
}

// AESGCMOpen takes raw key + iv + ciphertext_with_tag and returns plaintext.
func AESGCMOpen(key, iv, ciphertext []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("key must be 32 bytes (AES-256)")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(iv) != gcm.NonceSize() {
		return nil, errors.New("iv length mismatch")
	}
	return gcm.Open(nil, iv, ciphertext, nil)
}

// AESGCMSealSplitWithAAD is AESGCMSealSplit with additional authenticated data
// (AAD) bound into the GCM tag. The AAD is authenticated but not encrypted, so
// the same aad bytes must be supplied to AESGCMOpenWithAAD to open. Used to bind
// a sealed payload to its canonical context (org_id|entry_id|payload_kind|
// schema_version|dek_version) so a ciphertext cannot be swapped between contexts.
//
// aesGCMSealSplit / AESGCMOpen (the AAD=nil siblings) are unchanged.
func AESGCMSealSplitWithAAD(key, plaintext, aad []byte) ([]byte, []byte, error) {
	if len(key) != 32 {
		return nil, nil, errors.New("key must be 32 bytes (AES-256)")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	iv := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(iv); err != nil {
		return nil, nil, err
	}
	ciphertext := gcm.Seal(nil, iv, plaintext, aad)
	return iv, ciphertext, nil
}

// AESGCMOpenWithAAD is AESGCMOpen with additional authenticated data. Opening
// fails (tag mismatch) unless aad is byte-identical to the aad used when
// sealing — this is the swap-prevention guarantee.
func AESGCMOpenWithAAD(key, iv, ciphertext, aad []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("key must be 32 bytes (AES-256)")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(iv) != gcm.NonceSize() {
		return nil, errors.New("iv length mismatch")
	}
	return gcm.Open(nil, iv, ciphertext, aad)
}

// ────────────────────────────────────────────────────────────────────────
// Lowercase aliases — used by callers inside the handlers/ package via shorter names.
// ────────────────────────────────────────────────────────────────────────

func aesGCMSeal(k, p []byte) (string, error) { return AESGCMSeal(k, p) }
func aesGCMSealSplit(k, p []byte) ([]byte, []byte, error) {
	return AESGCMSealSplit(k, p)
}
func aesGCMOpen(k, iv, c []byte) ([]byte, error) { return AESGCMOpen(k, iv, c) }
func aesGCMSealSplitWithAAD(k, p, aad []byte) ([]byte, []byte, error) {
	return AESGCMSealSplitWithAAD(k, p, aad)
}
