// Package keychain — OS Keychain abstraction for the keeper keystore.
//
// keeper runs on top of macOS Keychain / Linux Secret Service / Windows
// Credential Manager (go-keyring abstracts the per-OS backend). Unit tests
// swap it out for a process-local map via `keyring.MockInit()`.
//
// **DI motivation:** "How do you test the OS Keychain dependency?" is the
// first question in any public review. Introducing the SecretStore interface:
//
//   - Standard unit tests can run without macOS Keychain (inject in-memory
//     store)
//   - Cleanly separates Linux/Windows implementation branches
//   - e2e keyring file mode and production mode are handled through the same
//     interface
//
// Exposes SecretStore + KeyringSecretStore + MemorySecretStore on the App
// struct. Free helper functions (krSet/krGet/krDelete) are also available
// for callers that don't yet hold an App reference.
package keychain

import (
	"errors"
	"sync"

	"github.com/zalando/go-keyring"
)

// ErrSecretNotFound lets SecretStore implementations return a consistent
// sentinel. The keyring package exposes `keyring.ErrNotFound`, but importing
// that directly from external code increases coupling, so this alias lives
// inside the keystore package.
var ErrSecretNotFound = errors.New("secret not found")

// SecretStore is the minimum contract for an OS Keychain-style secret store.
// Get / Set / Delete cover every storage flow in the keystore package.
//
//   - Get: returns ErrSecretNotFound (or a wrapping error) when missing.
//   - Set: calling twice on the same (service, account) overwrites.
//   - Delete: deleting a missing entry may return an error (same as keyring).
type SecretStore interface {
	Get(service, account string) (string, error)
	Set(service, account, value string) error
	Delete(service, account string) error
}

// KeyringSecretStore is the production SecretStore — delegates to
// `krSet/krGet/krDelete`. This way (1) the e2e KEEPER_E2E_KEYRING_FILE file
// mirror is applied automatically, and (2) `app.Store.X(...)` and a direct
// `krX(...)` call have equivalent semantics → storage.go behaves the same
// whichever path is used.
//
// Previously KeyringSecretStore called keyring.* directly and bypassed the
// file mirror; delegating to kr* lets both paths share the same mirror.
type KeyringSecretStore struct{}

func (KeyringSecretStore) Get(service, account string) (string, error) {
	v, err := krGet(service, account)
	if err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			return "", ErrSecretNotFound
		}
		return "", err
	}
	return v, nil
}

func (KeyringSecretStore) Set(service, account, value string) error {
	return krSet(service, account, value)
}

func (KeyringSecretStore) Delete(service, account string) error {
	return krDelete(service, account)
}

// MemorySecretStore is an in-memory SecretStore for unit tests.
// Similar to keyring.MockInit(), but isolated per instance rather than
// process-global, so parallel tests are safe. Returns the last Set value for
// the same (service, account) pair; ErrSecretNotFound when missing.
//
// mu is intentionally a plain sync.Mutex — a small pattern that does not
// warrant an RWMutex.
type MemorySecretStore struct {
	mu      sync.Mutex
	entries map[string]string
}

// NewMemorySecretStore returns an empty store.
func NewMemorySecretStore() *MemorySecretStore {
	return &MemorySecretStore{entries: make(map[string]string)}
}

func (s *MemorySecretStore) key(service, account string) string {
	return service + "|" + account
}

func (s *MemorySecretStore) Get(service, account string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.entries[s.key(service, account)]
	if !ok {
		return "", ErrSecretNotFound
	}
	return v, nil
}

func (s *MemorySecretStore) Set(service, account, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[s.key(service, account)] = value
	return nil
}

func (s *MemorySecretStore) Delete(service, account string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := s.key(service, account)
	if _, ok := s.entries[k]; !ok {
		return ErrSecretNotFound
	}
	delete(s.entries, k)
	return nil
}

// Size returns the current entry count (for test assertions).
func (s *MemorySecretStore) Size() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries)
}
