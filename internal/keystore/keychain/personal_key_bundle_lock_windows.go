//go:build windows

package keychain

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

func acquirePersonalKeyBundleProcessLock() (func(), error) {
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
	if err := windows.LockFileEx(windows.Handle(file.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, &overlapped); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("acquire personal key bundle lock: %w", err)
	}
	return func() {
		_ = windows.UnlockFileEx(windows.Handle(file.Fd()), 0, 1, 0, &overlapped)
		_ = file.Close()
	}, nil
}
