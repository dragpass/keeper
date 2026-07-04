package crypto

import (
	stdcrypto "crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// RSAPSSOptions returns the PSS options used for signing and verification.
// SaltLength matches the hash output size (SHA-256 = 32 bytes) per RFC 8017.
//
// Exported so root_pubkey.go in the keystore root package can share the same
// options. Internal callers in this package should also use this helper to
// keep algorithm parameters in one place.
func RSAPSSOptions() *rsa.PSSOptions {
	return &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       stdcrypto.SHA256,
	}
}

type KeyPair struct {
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
}

// GenerateRSAKeyPair generates a new RSA key pair and returns it in PEM format
func GenerateRSAKeyPair() (*KeyPair, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	// Convert private key to PEM format
	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %v", err)
	}
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyDER,
	})

	// Extract public key from the private key
	publickey := &privateKey.PublicKey

	// Convert public key to PEM format
	publickeyDER, err := x509.MarshalPKIXPublicKey(publickey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %v", err)
	}

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publickeyDER,
	})

	return &KeyPair{
		PrivateKey: string(privateKeyPEM),
		PublicKey:  string(publicKeyPEM),
	}, nil
}

// ParsePrivateKey parses a PEM encoded private key
func ParsePrivateKey(privateKeyPEM string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	privateKeyInterface, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %v", err)
	}

	privateKey, ok := privateKeyInterface.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA private key")
	}

	return privateKey, nil
}

// ParsePublicKey parses a PEM encoded public key
func ParsePublicKey(publicKeyPEM string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	publicKeyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %v", err)
	}

	publicKey, ok := publicKeyInterface.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA public key")
	}

	return publicKey, nil
}

// PublicKeyToPEM converts a public key to PEM format
func PublicKeyToPEM(publicKey *rsa.PublicKey) (string, error) {
	publicKeyDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", fmt.Errorf("failed to marshal public key: %v", err)
	}

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyDER,
	})

	return string(publicKeyPEM), nil
}

// VerifySignature verifies the signature of the data using RSA-PSS with SHA-256.
func VerifySignature(publicKey *rsa.PublicKey, data string, signature []byte) error {
	hashed := sha256.Sum256([]byte(data))

	err := rsa.VerifyPSS(publicKey, stdcrypto.SHA256, hashed[:], signature, RSAPSSOptions())
	if err != nil {
		return fmt.Errorf("signature verification failed: %v", err)
	}

	return nil
}

// SignData signs the given data using RSA-PSS with SHA-256.
func SignData(privateKey *rsa.PrivateKey, data string) ([]byte, error) {
	hashed := sha256.Sum256([]byte(data))

	signature, err := rsa.SignPSS(rand.Reader, privateKey, stdcrypto.SHA256, hashed[:], RSAPSSOptions())
	if err != nil {
		return nil, fmt.Errorf("failed to sign data: %v", err)
	}

	return signature, nil
}

// DecryptData decrypts the given encrypted data using the provided private key
func DecryptData(privateKey *rsa.PrivateKey, encryptedData []byte) ([]byte, error) {
	// Decrypt the data using RSA OAEP
	decryptedData, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, encryptedData, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %v", err)
	}

	return decryptedData, nil
}

// EncryptData encrypts the given plaintext using the provided public key.
// RSA-OAEP with SHA-256 (MGF1-SHA256, empty label) — interoperable with Web
// Crypto API (RSA-OAEP + hash=SHA-256).
//
// Used by Group DEK wrapping: Extension sends Group DEK raw 32B to Keeper
// together with the recipient member's public key PEM, and receives the
// wrapped ciphertext back. The plaintext Group DEK never leaves the Keeper
// process unless it was the caller's own copy to begin with (the caller
// typically already holds it in the session cache).
func EncryptData(publicKey *rsa.PublicKey, plaintext []byte) ([]byte, error) {
	encryptedData, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, plaintext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt data: %v", err)
	}
	return encryptedData, nil
}
