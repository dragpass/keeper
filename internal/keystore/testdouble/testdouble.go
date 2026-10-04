// Package testdouble holds the in-memory stand-ins unit tests inject through
// Deps: a secret store, a capturing logger, and server signature verifiers
// that always pass or always fail.
//
// Only _test.go files may import it. AlwaysOKVerifier accepts every server
// signature, so a production path that reached it would trust anything the
// server is supposed to have signed. TestNoProductionPackageImportsTestDouble
// keeps the production import graph free of this package.
package testdouble

import (
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/dragpass/keeper/internal/keystore/keychain"
)

// MemorySecretStore is an in-memory keychain.SecretStore. Similar to
// keyring.MockInit(), but isolated per instance rather than process-global, so
// parallel tests are safe. Returns the last Set value for the same
// (service, account) pair; keychain.ErrSecretNotFound when missing.
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
		return "", keychain.ErrSecretNotFound
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
		return keychain.ErrSecretNotFound
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

// Size returns the current entry count.
func (s *MemorySecretStore) Size() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries)
}

// MemoryLogger keeps every message in a slice so that regression guards like
// "the secret was not echoed into the log" can be expressed as assertions. It
// satisfies logger.Logger.
type MemoryLogger struct {
	mu       sync.Mutex
	messages []string
}

// NewMemoryLogger creates a logger with an empty capture slice.
func NewMemoryLogger() *MemoryLogger {
	return &MemoryLogger{messages: make([]string, 0, 8)}
}

func (m *MemoryLogger) Println(args ...any) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.messages = append(m.messages, fmt.Sprintln(args...))
}

func (m *MemoryLogger) Printf(format string, args ...any) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.messages = append(m.messages, fmt.Sprintf(format, args...))
}

// Messages returns a copy of the captured messages, so a caller mutating it
// cannot race with later writes.
func (m *MemoryLogger) Messages() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, len(m.messages))
	copy(out, m.messages)
	return out
}

// Contains reports whether any captured message contains substr.
func (m *MemoryLogger) Contains(substr string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, msg := range m.messages {
		if strings.Contains(msg, substr) {
			return true
		}
	}
	return false
}

// Reset clears all captured messages.
func (m *MemoryLogger) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.messages = m.messages[:0]
}

// AlwaysOKVerifier returns nil for every input, to pass a handler's verify
// step and assert on what follows.
type AlwaysOKVerifier struct{}

func (AlwaysOKVerifier) Verify(token string, sigB64 string, serverKeyVersion uint) error {
	return nil
}

// AlwaysFailVerifier returns the same error for every input, to assert what a
// handler does when verify fails.
type AlwaysFailVerifier struct {
	Err error
}

func (v AlwaysFailVerifier) Verify(token string, sigB64 string, serverKeyVersion uint) error {
	if v.Err == nil {
		return errors.New("server signature verification failed: stub")
	}
	return v.Err
}
