package keystore

// test_helpers_test.go — test-only helpers shared across keystore root tests.
//
// withTempRootPublicKey / generateRootKeypairForTest / signRootPayloadForTest
// / setKeychainDeviceKey / resetServerKeySlots live in the handlers/ package
// (refresh_server_keys_test / dek_rewrap_test / rotate_keypair_test). Root
// facade tests use a fresh helper that builds NewApp + testdouble.MemorySecretStore to
// isolate dispatcher JSON scenarios.

import (
	"testing"

	"github.com/dragpass/keeper/internal/keystore/clipboard"
	keepercrypto "github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/testdouble"
)

func setupAppKeyPair(t *testing.T, app *App) (publicKeyPEM, privateKeyPEM string) {
	t.Helper()
	kp, err := keepercrypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("GenerateRSAKeyPair: %v", err)
	}
	if err := keychain.SavePublicKey(app.Store, kp.PublicKey); err != nil {
		t.Fatalf("savePublicKey: %v", err)
	}
	if err := keychain.SavePrivateKey(app.Store, kp.PrivateKey); err != nil {
		t.Fatalf("savePrivateKey: %v", err)
	}
	return kp.PublicKey, kp.PrivateKey
}

func newFacadeTestApp() *App {
	// Use an in-memory clipboard so tests behave consistently in headless CI.
	return NewApp(Deps{
		Store:     testdouble.NewMemorySecretStore(),
		Logger:    testdouble.NewMemoryLogger(),
		Clipboard: clipboard.NewMemoryClipboard(),
	})
}
