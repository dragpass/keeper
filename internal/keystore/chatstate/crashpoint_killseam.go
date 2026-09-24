//go:build keeper_killseam

package chatstate

import (
	"os"
	"strconv"
	"time"
)

// Environment of a keeper_killseam build: the point to stop at, how many
// earlier passes through it to let go by, and the file to create once there.
const (
	CrashPointEnvVar = "KEEPER_TEST_CRASH_AT"
	CrashSkipEnvVar  = "KEEPER_TEST_CRASH_SKIP"
	CrashMarkEnvVar  = "KEEPER_TEST_CRASH_MARK"
)

func init() {
	target := os.Getenv(CrashPointEnvVar)
	mark := os.Getenv(CrashMarkEnvVar)
	if target == "" || mark == "" {
		return
	}
	skip, _ := strconv.Atoi(os.Getenv(CrashSkipEnvVar))
	crashAt = func(point string) {
		if point != target {
			return
		}
		if skip > 0 {
			skip--
			return
		}
		// Parked, not exited: the harness looks at the disk while the process
		// holds the conversation lock, then sends the SIGKILL itself. A sleep
		// rather than an empty select so the runtime never reads this as a
		// deadlock and exits on its own.
		if f, err := os.Create(mark); err == nil {
			_ = f.Sync()
			_ = f.Close()
		}
		for {
			time.Sleep(time.Hour)
		}
	}
}
