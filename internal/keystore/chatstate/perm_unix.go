//go:build !windows

package chatstate

import "os"

func restrictFileToOwner(path string) error { return os.Chmod(path, 0o600) }

func restrictDirToOwner(path string) error { return os.Chmod(path, 0o700) }
