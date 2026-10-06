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

// withPersonalKeyBundleLock is the keychain process lock: an in-process mutex
// in front of a cross-process file lock. Neither half is reentrant, so fn
// must use only the ...Locked helpers. A read-check-write that must not be
// split by another process is one keychain function taking a callback
// (AdoptPersonalDeviceWrappedDEK, SealPersonalDeviceWrappedDEK, EnsureDeviceKey),
// not a lock scope opened by a handler: a handler would hold it across RSA
// key generation or PBKDF2, and another process waits for it at most
// personalKeyBundleLockTimeout.
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

func WithKeychainProcessLock(store SecretStore, fn func() error) error {
	return withPersonalKeyBundleLock(store, fn)
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
