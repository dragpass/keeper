package keychain

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

const (
	personalKeyBundleLockTimeout = 5 * time.Second
	personalKeyBundleLockRetry   = 25 * time.Millisecond
)

var errPersonalKeyBundleLockTimeout = errors.New("personal key bundle lock timeout")

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
	_, ok := store.(platformKeyringBackedStore)
	return ok
}

type platformKeyringBackedStore interface {
	usesPlatformKeyring()
}

func waitForPersonalKeyBundleProcessLock(
	timeout time.Duration,
	tryLock func() (bool, error),
) error {
	deadline := time.Now().Add(timeout)
	for {
		acquired, err := tryLock()
		if err != nil {
			return err
		}
		if acquired {
			return nil
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return fmt.Errorf("%w after %s", errPersonalKeyBundleLockTimeout, timeout)
		}
		if remaining < personalKeyBundleLockRetry {
			time.Sleep(remaining)
		} else {
			time.Sleep(personalKeyBundleLockRetry)
		}
	}
}
