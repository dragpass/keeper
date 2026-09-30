//go:build windows

package chatstate

import (
	"fmt"
	"path/filepath"

	"golang.org/x/sys/windows"
)

func replaceStateFile(source, target string) error {
	longSource, err := windowsLongPath(source)
	if err != nil {
		return err
	}
	longTarget, err := windowsLongPath(target)
	if err != nil {
		return err
	}
	from, err := windows.UTF16PtrFromString(longSource)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(longTarget)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}

func windowsLongPath(path string) (string, error) {
	if len(path) < 248 || len(path) >= 4 && path[:4] == `\\?\` {
		return path, nil
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve state path: %w", err)
	}
	if len(abs) >= 2 && abs[:2] == `\\` {
		return `\\?\UNC\` + abs[2:], nil
	}
	return `\\?\` + abs, nil
}

// syncDir has no Windows counterpart that this repo has established. The ADR
// lists both this and the durability of a rename over an existing file as
// things to measure before the Windows path is claimed to be fully atomic. The
// replacement itself requests write-through; directory metadata flushing is
// still not established here.
func syncDir(string) error { return nil }
