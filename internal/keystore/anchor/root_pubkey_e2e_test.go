//go:build keeper_e2e

package anchor

import (
	"encoding/base64"
	"testing"
)

// A keeper_e2e build lets a test supply its own root key, and a root key
// embedded at build time still wins over it.
func TestE2ERootPublicKeyEnvironmentOverride(t *testing.T) {
	old := rootPublicKeyPEMBase64
	rootPublicKeyPEMBase64 = ""
	t.Cleanup(func() { rootPublicKeyPEMBase64 = old })
	const envPEM = "-----BEGIN PUBLIC KEY-----\nENV\n-----END PUBLIC KEY-----\n"
	t.Setenv(rootPublicKeyEnvVar, base64.StdEncoding.EncodeToString([]byte(envPEM)))

	if pem, err := RootPublicKeyPEM(); err != nil || pem != envPEM {
		t.Fatalf("RootPublicKeyPEM = %q, %v; want the env key", pem, err)
	}

	const embeddedPEM = "-----BEGIN PUBLIC KEY-----\nEMBEDDED\n-----END PUBLIC KEY-----\n"
	rootPublicKeyPEMBase64 = base64.StdEncoding.EncodeToString([]byte(embeddedPEM))
	if pem, err := RootPublicKeyPEM(); err != nil || pem != embeddedPEM {
		t.Fatalf("RootPublicKeyPEM = %q, %v; want the embedded key", pem, err)
	}
}
