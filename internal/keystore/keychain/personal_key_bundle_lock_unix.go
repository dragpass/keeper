//go:build darwin || linux

package keychain

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

func acquirePersonalKeyBundleProcessLock() (func(), error) {
	return acquirePersonalKeyBundleProcessLockWithTimeout(personalKeyBundleLockTimeout)
}

func acquirePersonalKeyBundleProcessLockWithTimeout(timeout time.Duration) (func(), error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return nil, fmt.Errorf("resolve personal key bundle lock directory: %w", err)
	}
	dir = filepath.Join(dir, "dragpass-keeper")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create personal key bundle lock directory: %w", err)
	}
	file, err := os.OpenFile(filepath.Join(dir, "personal-key-bundle.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open personal key bundle lock: %w", err)
	}
	if err := waitForPersonalKeyBundleProcessLock(timeout, func() (bool, error) {
		err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return true, nil
		}
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return false, nil
		}
		return false, err
	}); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("acquire personal key bundle lock: %w", err)
	}
	return func() {
		_ = unix.Flock(int(file.Fd()), unix.LOCK_UN)
		_ = file.Close()
	}, nil
}
