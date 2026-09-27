//go:build !windows

package localsecret

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// checkPrivate refuses anything another user could read or replace. Another
// user who could write this directory could plant a secret of their own and
// then impersonate the owner to the proxy.
func checkPrivate(path string, wantDir bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect Keeper local secret path: %w", err)
	}
	if wantDir != info.IsDir() || (!wantDir && !info.Mode().IsRegular()) {
		return errors.New("Keeper local secret path has the wrong type")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return errors.New("Keeper local secret path is accessible to other users")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Getuid() {
		return errors.New("Keeper local secret path is owned by another user")
	}
	return nil
}

// tightenOwnDir repairs a directory this user owns but left group- or
// world-accessible (MkdirAll keeps an existing directory's mode). A directory
// owned by someone else is refused, never adopted.
func tightenOwnDir(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect Keeper local secret directory: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !info.IsDir() || !ok || int(stat.Uid) != os.Getuid() {
		return errors.New("Keeper local secret directory is not owned by this user")
	}
	if info.Mode().Perm()&0o077 == 0 {
		return nil
	}
	return os.Chmod(path, 0o700)
}
