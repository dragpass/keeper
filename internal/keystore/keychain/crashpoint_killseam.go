//go:build keeper_killseam

package keychain

import (
	"os"
	"time"
)

// The same environment the chatstate seam reads (chatstate/crashpoint_killseam.go);
// only the package whose point is named stops.
func init() {
	target := os.Getenv("KEEPER_TEST_CRASH_AT")
	mark := os.Getenv("KEEPER_TEST_CRASH_MARK")
	if target == "" || mark == "" {
		return
	}
	crashAt = func(point string) {
		if point != target {
			return
		}
		if f, err := os.Create(mark); err == nil {
			_ = f.Sync()
			_ = f.Close()
		}
		for {
			time.Sleep(time.Hour)
		}
	}
}
