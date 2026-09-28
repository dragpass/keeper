package keychain

import (
	"fmt"
	"path/filepath"
	"sync"
	"testing"

	"github.com/zalando/go-keyring"
)

// The App signs its requests concurrently (several console calls after a
// page load), and each signature reads the request key through krGet. In e2e
// mode every read reloads the mirror file into the shared snapshot map, so
// concurrent reads and writes must not touch that map unguarded: an e2e
// Keeper died with "fatal error: concurrent map writes" in the browser e2e.
func TestFileMirrorConcurrentReadsAndWrites(t *testing.T) {
	keyring.MockInit()
	t.Setenv(e2eKeyringFileEnvVar, filepath.Join(t.TempDir(), "keyring.json"))
	if err := krSet("svc", "seed", "v"); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	for i := range 16 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for range 50 {
				if _, err := krGet("svc", "seed"); err != nil {
					t.Error(err)
					return
				}
			}
		}()
		go func() {
			defer wg.Done()
			for j := range 20 {
				if err := krSet("svc", fmt.Sprintf("k%d-%d", i, j), "v"); err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	wg.Wait()

	for i := range 16 {
		for j := range 20 {
			if _, err := krGet("svc", fmt.Sprintf("k%d-%d", i, j)); err != nil {
				t.Fatalf("k%d-%d lost: %v", i, j, err)
			}
		}
	}
}
