//go:build mls && cgo && windows

package killharness

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
)

// forceKill is TerminateProcess (os.Process.Kill on Windows): like SIGKILL it
// runs no deferred function, no atexit handler and no flush of user-space
// buffers, and the kernel releases the process's handles, the LockFileEx
// locks included, only after it is gone. For what these tests assert, what an
// interrupted write leaves on disk and what a restart makes of it, the two are
// equivalent. TerminateProcess is asynchronous, so every caller waits on the
// process before looking at the disk.
func forceKill(p *os.Process) error { return p.Kill() }

// diedOfForceKill reports whether a Wait error is the exit code Go's Kill
// hands TerminateProcess (1). A Keeper never exits 1 on its own while parked
// at a crash point or serving requests, so the code is not ambiguous here.
func diedOfForceKill(err error) bool {
	var exit *exec.ExitError
	return errors.As(err, &exit) && exit.ExitCode() == 1
}

const binarySuffix = ".exe"

// platformEnv is what a Windows process needs beyond the harness's own
// variables: the system root (DLL loading, the CSPRNG) and per-device
// profile directories, so nothing reaches the runner's real profile.
func platformEnv(dir string) []string {
	return []string{
		"SystemRoot=" + os.Getenv("SystemRoot"),
		"SYSTEMROOT=" + os.Getenv("SystemRoot"),
		"TEMP=" + os.TempDir(),
		"TMP=" + os.TempDir(),
		"USERPROFILE=" + filepath.Join(dir, "home"),
		"APPDATA=" + filepath.Join(dir, "home", "AppData", "Roaming"),
		"LOCALAPPDATA=" + filepath.Join(dir, "home", "AppData", "Local"),
	}
}
