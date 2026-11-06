package crypto

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
)

// RewrapKeyFingerprint identifies the RSA key Keeper actually parses for a
// signed rewrap decision. Account pins still hash the exact PEM bytes.
func RewrapKeyFingerprint(publicKeyPEM string) (string, error) {
	key, err := ParsePublicKey(publicKeyPEM)
	if err != nil {
		return "", err
	}
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:]), nil
}
