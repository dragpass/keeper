package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/zalando/go-keyring"

	"github.com/dragpass/keeper/config"
	"github.com/dragpass/keeper/internal/keystore/testdouble"
)

// realKeychainTestEnv opts in to TestArchiveSplitJournalItemsInTheRealKeychain.
const realKeychainTestEnv = "KEEPER_REAL_KEYCHAIN_TEST"

// The split journal items of the largest record (32 recipients), written,
// read back and deleted through the real go-keyring backend of this machine under a
// throwaway service name. Opt-in, because CI runners may have no unlocked
// keychain and other tests in this package replace the keyring with its mock
// (keyring.MockInit) for the rest of the process. Run it alone:
//
//	KEEPER_REAL_KEYCHAIN_TEST=1 go test ./internal/keystore/handlers/ \
//	  -run '^TestArchiveSplitJournalItemsInTheRealKeychain$' -count=1 -v
//
// It never touches config.Service, and removes every item it wrote.
func TestArchiveSplitJournalItemsInTheRealKeychain(t *testing.T) {
	if os.Getenv(realKeychainTestEnv) != "1" {
		t.Skipf("set %s=1 and run this test alone to use the real keychain", realKeychainTestEnv)
	}
	var random [8]byte
	if _, err := rand.Read(random[:]); err != nil {
		t.Fatal(err)
	}
	service := "dragpass-keeper-split-size-test-" + hex.EncodeToString(random[:])
	if service == config.Service || strings.HasPrefix(config.Service, service) {
		t.Fatal("throwaway service collides with the Keeper service")
	}
	for _, n := range []int{32} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			c := newSplitCase(t, "activation", n)
			split := c.split(t)
			if !split.Success {
				t.Fatal(split.ErrorCode)
			}
			items := map[string]string{}
			for key, value := range c.f.store.(*testdouble.MemorySecretStore).Snapshot() {
				if _, account, _ := strings.Cut(key, "|"); strings.HasPrefix(account, splitJournalPrefix) {
					items[account] = value
				}
			}
			accounts := make([]string, 0, len(items))
			largest := 0
			for account, value := range items {
				accounts = append(accounts, account)
				largest = max(largest, len(value))
			}
			sort.Strings(accounts)
			var written []string
			t.Cleanup(func() {
				for _, account := range written {
					if err := keyring.Delete(service, account); err != nil && !errors.Is(err, keyring.ErrNotFound) {
						t.Errorf("cleanup of %s: %v", account, err)
					}
				}
			})
			start := time.Now()
			for i, account := range accounts {
				// Registered first: a Set that stored the item but returned an
				// error still leaves it for cleanup.
				written = append(written, account)
				if err := keyring.Set(service, account, items[account]); err != nil {
					if i == 0 && !errors.Is(err, keyring.ErrSetDataTooBig) {
						t.Skipf("no usable OS keychain here: %v", err)
					}
					t.Fatalf("set %s (%d bytes): %v", account, len(items[account]), err)
				}
			}
			setTime := time.Since(start)
			if runtime.GOOS == "darwin" {
				// The item is in the login keychain, not in a keyring mock.
				if err := exec.Command("/usr/bin/security", "find-generic-password", "-s", service, "-a", accounts[0]).Run(); err != nil {
					t.Fatalf("item not found by /usr/bin/security: %v", err)
				}
			}
			start = time.Now()
			for _, account := range accounts {
				got, err := keyring.Get(service, account)
				if err != nil || got != items[account] {
					t.Fatalf("read back %s: %v", account, err)
				}
			}
			getTime := time.Since(start)
			start = time.Now()
			for _, account := range accounts {
				if err := keyring.Delete(service, account); err != nil {
					t.Fatalf("delete %s: %v", account, err)
				}
			}
			deleteTime := time.Since(start)
			for _, account := range accounts {
				if _, err := keyring.Get(service, account); !errors.Is(err, keyring.ErrNotFound) {
					t.Fatalf("%s still present after delete: %v", account, err)
				}
			}
			written = nil
			t.Logf("%s: %d recipients, %d items, largest %d bytes; set %v, get %v, delete %v",
				runtime.GOOS, n, len(accounts), largest, setTime.Round(time.Millisecond), getTime.Round(time.Millisecond), deleteTime.Round(time.Millisecond))
		})
	}
}
