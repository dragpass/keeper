//go:build darwin || linux

package keychain

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
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
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("acquire personal key bundle lock: %w", err)
	}
	return func() {
		_ = unix.Flock(int(file.Fd()), unix.LOCK_UN)
		_ = file.Close()
	}, nil
}
