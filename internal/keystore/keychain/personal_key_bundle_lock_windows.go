//go:build windows

package keychain

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows"
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
	var overlapped windows.Overlapped
	if err := waitForPersonalKeyBundleProcessLock(timeout, func() (bool, error) {
		err := windows.LockFileEx(
			windows.Handle(file.Fd()),
			windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
			0,
			1,
			0,
			&overlapped,
		)
		if err == nil {
			return true, nil
		}
		if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			return false, nil
		}
		return false, err
	}); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("acquire personal key bundle lock: %w", err)
	}
	return func() {
		_ = windows.UnlockFileEx(windows.Handle(file.Fd()), 0, 1, 0, &overlapped)
		_ = file.Close()
	}, nil
}
