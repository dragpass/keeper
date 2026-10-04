// memory_store_test.go — this package's own in-memory store and a logger
// that drops everything.
//
// Other packages' tests use testdouble. This package cannot: testdouble
// imports keychain for ErrSecretNotFound, so importing it here would be an
// import cycle.

package keychain

import "sync"

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

// Snapshot copies every entry, keyed service|account (for test assertions
// that nothing but the entries a test expects changed).
func (s *MemorySecretStore) Snapshot() map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]string, len(s.entries))
	for k, v := range s.entries {
		out[k] = v
	}
	return out
}

// Size returns the current entry count (for test assertions).
func (s *MemorySecretStore) Size() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries)
}

type discardLogger struct{}

func (discardLogger) Println(...any)        {}
func (discardLogger) Printf(string, ...any) {}
