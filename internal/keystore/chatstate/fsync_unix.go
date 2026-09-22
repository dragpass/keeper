//go:build darwin || linux

package chatstate

import "os"

// syncDir flushes the directory entry the rename created. Without it the rename
// can still be in the log when the machine loses power, which would take the
// new file with it.
func syncDir(dir string) error {
	handle, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer handle.Close()
	return handle.Sync()
}
