//go:build mls && cgo

package mls

import (
	"bytes"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// The Rust library keeps its last error in a thread-local slot that Go reads
// with a second cgo call. Each failing call must report its own error even
// when goroutines move between OS threads, which happens under load (CI).
// Two kinds of failure run side by side and each must see its own message.
func TestFailuresReportTheirOwnErrorAcrossThreads(t *testing.T) {
	const workers, rounds = 64, 3000
	var wg sync.WaitGroup
	var mu sync.Mutex
	wrong := 0
	sample := ""
	for w := 0; w < workers; w++ {
		s := newSession(t, "thread-"+string(rune('a'+w%26)))
		wg.Add(1)
		go func(w int, s *Session) {
			defer wg.Done()
			for i := 0; i < rounds; i++ {
				var err error
				want := ": mls: key package entry is malformed"
				if (w+i)%2 == 0 {
					_, _, err = s.KeyPackages(1, uint64(time.Now().Add(-time.Hour).Unix()))
					want = ": mls: the leaf declaration has already expired"
				} else {
					err = s.installKeyPackage(bytes.Repeat([]byte{1}, 3))
				}
				if err == nil || !strings.HasSuffix(err.Error(), want) {
					mu.Lock()
					wrong++
					if err != nil && sample == "" {
						sample = "want suffix " + want + ", got " + err.Error()
					}
					mu.Unlock()
				}
				runtime.Gosched()
			}
		}(w, s)
	}
	wg.Wait()
	if wrong != 0 {
		t.Fatalf("%d failures reported another call's error, e.g. %s", wrong, sample)
	}
}
