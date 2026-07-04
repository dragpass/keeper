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
	// MemoryClipboard 주입 — production fallback (`NewProductionClipboard`) 은
	// Linux 컨테이너 / 헤드리스 CI 에서 `Write` 가 `ErrUnavailable` 반환해
	// clipboard sink 를 사용하는 AES / DEK→clipboard handler 회귀 테스트가
	// 실패한다. macOS 로컬은 production clipboard 가 살아있어 통과하지만 CI
	// 부터 회귀 발견되는 비대칭이 생긴다.
	return NewApp(Deps{
		Store:     NewMemorySecretStore(),
		Logger:    NewMemoryLogger(),
		Clipboard: clipboard.NewMemoryClipboard(),
	})
}
