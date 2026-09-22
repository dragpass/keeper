//go:build windows

package chatstate

import (
	"errors"
	"fmt"
	"time"

	"golang.org/x/sys/windows"
)

func acquireFileLock(path string, timeout time.Duration) (func(), error) {
	file, err := openLockFile(path)
	if err != nil {
		return nil, fmt.Errorf("open chat state lock: %w", err)
	}
	var overlapped windows.Overlapped
	err = waitForFileLock(timeout, func() (bool, error) {
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
	})
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	return func() {
		_ = windows.UnlockFileEx(windows.Handle(file.Fd()), 0, 1, 0, &overlapped)
		_ = file.Close()
	}, nil
}
