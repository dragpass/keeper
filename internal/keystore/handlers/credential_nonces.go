// credential_nonces.go — the process-local execution nonces that make one
// signed credential policy usable once.
//
// credential_execution_prepare mints a nonce and remembers it here. The server
// signs that nonce into the policy it returns from resolve, and the first sink
// request that presents the policy consumes it. That is what turns "one
// approval, one resolve" (the server's guarded approval consumption) into "one
// resolve, at most one execution attempt":
//
//   - Consume deletes and returns in one critical section, so two concurrent
//     requests with the same policy leave exactly one winner.
//   - Nothing is persisted. A restart empties the map, so every policy that
//     names an outstanding nonce becomes unusable; there is no record that a
//     backup restore could roll back or a deletion could clear.
//   - Another Keeper process (another MCP server, dragpass-run, another device
//     of the same account) never minted the nonce and refuses it.
//
// The map holds no key material: a nonce and a deadline.

package handlers

import (
	"errors"
	"sync"
	"time"
)

const (
	// credentialNonceTTL — how long a minted nonce stays usable. It covers the
	// approval window (ariadne approvalTTL, 10 minutes) because the MCP client
	// prepares once per tool call and polls resolve while a person decides.
	// The signed policy's own 5 minute expiry still applies on top.
	credentialNonceTTL = 10 * time.Minute

	// credentialMaxNonces — live nonces per process. A full map refuses a new
	// prepare rather than evicting an older nonce: eviction would let a caller
	// cancel a use it does not own.
	credentialMaxNonces = 256
)

var errCredentialNoncesFull = errors.New("credential execution nonce capacity reached")

// CredentialNonceStore is the per-process nonce map. App owns one and injects
// it through Deps. A nil store fails closed: no nonce can be minted or consumed,
// so the credential sinks are unavailable rather than unguarded.
type CredentialNonceStore struct {
	mu      sync.Mutex
	entries map[string]time.Time
}

func NewCredentialNonceStore() *CredentialNonceStore {
	return &CredentialNonceStore{entries: make(map[string]time.Time)}
}

// Put registers a freshly minted nonce and returns its deadline.
func (s *CredentialNonceStore) Put(nonce string, now time.Time) (time.Time, error) {
	if s == nil {
		return time.Time{}, errCredentialNoncesFull
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for n, deadline := range s.entries {
		if !now.Before(deadline) {
			delete(s.entries, n)
		}
	}
	if len(s.entries) >= credentialMaxNonces {
		return time.Time{}, errCredentialNoncesFull
	}
	deadline := now.Add(credentialNonceTTL)
	s.entries[nonce] = deadline
	return deadline, nil
}

// Consume deletes the nonce and reports whether it was live. Whoever wins the
// lock gets true; every other caller, and every later one, gets false.
func (s *CredentialNonceStore) Consume(nonce string, now time.Time) bool {
	if s == nil || nonce == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	deadline, ok := s.entries[nonce]
	if !ok {
		return false
	}
	delete(s.entries, nonce)
	return now.Before(deadline)
}

// Len reports the live entry count, for tests.
func (s *CredentialNonceStore) Len() int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries)
}
