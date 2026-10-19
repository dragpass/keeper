//go:build !keeper_e2e

package anchor

import (
	"encoding/base64"
	"errors"
	"testing"
)

// A release Keeper takes its root key only from the build (-ldflags); the
// environment cannot choose the key that signs server public keys.
func TestReleaseRootPublicKeyIgnoresTheEnvironment(t *testing.T) {
	old := rootPublicKeyPEMBase64
	rootPublicKeyPEMBase64 = ""
	t.Cleanup(func() { rootPublicKeyPEMBase64 = old })
	t.Setenv("KEEPER_ROOT_PUBLIC_KEY_BASE64", base64.StdEncoding.EncodeToString([]byte("-----BEGIN PUBLIC KEY-----\nX\n-----END PUBLIC KEY-----\n")))

	pem, err := RootPublicKeyPEM()
	if err != nil || pem != "" {
		t.Fatalf("RootPublicKeyPEM = %q, %v; want no root key", pem, err)
	}
	if err := VerifyServerKeyRootSignature([]byte("payload"), []byte("sig")); !errors.Is(err, ErrRootKeyNotConfigured) {
		t.Fatalf("VerifyServerKeyRootSignature err = %v, want ErrRootKeyNotConfigured", err)
	}
}
