//go:build darwin || linux

package chatstate

import (
	"errors"
	"fmt"
	"time"

	"golang.org/x/sys/unix"
)

func acquireFileLock(path string, timeout time.Duration) (func(), error) {
	file, err := openLockFile(path)
	if err != nil {
		return nil, fmt.Errorf("open chat state lock: %w", err)
	}
	err = waitForFileLock(timeout, func() (bool, error) {
		err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return true, nil
		}
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return false, nil
		}
		return false, err
	})
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	// Closing the descriptor releases the flock on its own; the explicit unlock
	// is there so a descriptor leak elsewhere cannot keep a conversation shut.
	return func() {
		_ = unix.Flock(int(file.Fd()), unix.LOCK_UN)
		_ = file.Close()
	}, nil
}
