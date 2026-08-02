package keystore

// test_helpers_test.go — test-only helpers shared across keystore root tests.
//
// withTempRootPublicKey / generateRootKeypairForTest / signRootPayloadForTest
// / setKeychainDeviceKey / resetServerKeySlots live in the handlers/ package
// (refresh_server_keys_test / dek_rewrap_test / rotate_keypair_test). Root
// facade tests use a fresh helper that builds NewApp + MemorySecretStore to
// isolate dispatcher JSON scenarios.

import (
	"testing"

	"github.com/dragpass/keeper/internal/keystore/clipboard"
	keepercrypto "github.com/dragpass/keeper/internal/keystore/crypto"
)

func setupAppKeyPair(t *testing.T, app *App) (publicKeyPEM, privateKeyPEM string) {
	t.Helper()
	kp, err := keepercrypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("GenerateRSAKeyPair: %v", err)
	}
	if err := app.savePublicKey(kp.PublicKey); err != nil {
		t.Fatalf("savePublicKey: %v", err)
	}
	if err := app.savePrivateKey(kp.PrivateKey); err != nil {
		t.Fatalf("savePrivateKey: %v", err)
	}
	return kp.PublicKey, kp.PrivateKey
}

func newFacadeTestApp() *App {
	// Use an in-memory clipboard so tests behave consistently in headless CI.
	return NewApp(Deps{
		Store:     NewMemorySecretStore(),
		Logger:    NewMemoryLogger(),
		Clipboard: clipboard.NewMemoryClipboard(),
	})
}
