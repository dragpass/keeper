package keychain

import "sync"

var personalKeyBundleMu sync.Mutex

func withPersonalKeyBundleLock(store SecretStore, fn func() error) error {
	personalKeyBundleMu.Lock()
	defer personalKeyBundleMu.Unlock()

	if !usesPlatformKeyring(store) {
		return fn()
	}
	unlock, err := acquirePersonalKeyBundleProcessLock()
	if err != nil {
		return err
	}
	defer unlock()
	return fn()
}

func usesPlatformKeyring(store SecretStore) bool {
	switch store.(type) {
	case KeyringSecretStore, *KeyringSecretStore:
		return true
	default:
		return false
	}
}
