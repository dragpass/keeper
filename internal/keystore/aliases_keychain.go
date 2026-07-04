// Keychain aliases — keystore package 내부 (storage.go / app.go / main.go) 가
// bare name / keystore.X 로 참조하는 type 과 main.go 가 호출하는 함수만 보존.

package keystore

import "github.com/dragpass/keeper/internal/keystore/keychain"

type (
	SecretStore        = keychain.SecretStore
	KeyringSecretStore = keychain.KeyringSecretStore
)

var (
	ErrSecretNotFound           = keychain.ErrSecretNotFound
	ErrServerKeyVersionNotFound = keychain.ErrServerKeyVersionNotFound
	ErrNoActiveServerKey        = keychain.ErrNoActiveServerKey
	LoadE2EKeyringFile          = keychain.LoadE2EKeyringFile
	NewMemorySecretStore        = keychain.NewMemorySecretStore
)
