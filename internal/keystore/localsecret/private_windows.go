//go:build windows

package localsecret

import (
	"errors"
	"fmt"
	"os"
)

// checkPrivate relies on the per-user profile ACL of os.UserConfigDir on
// Windows; POSIX mode bits carry no meaning there.
func checkPrivate(path string, wantDir bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect Keeper local secret path: %w", err)
	}
	if wantDir != info.IsDir() || (!wantDir && !info.Mode().IsRegular()) {
		return errors.New("Keeper local secret path has the wrong type")
	}
	return nil
}

func tightenOwnDir(string) error { return nil }
