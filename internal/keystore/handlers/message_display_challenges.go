// message_display_challenges.go — the process-local challenge map behind the
// two-step secure-message reveal.
//
// message_display_prepare mints a challenge and remembers the whole message
// context under it; group_decrypt_with_aad_for_app_display verifies a
// server-signed permit against that memory and consumes the entry. The map is
// what ties the server's authorization to *this* Keeper process and to one
// single reveal:
//
//   - The server signs a permit over a challenge without knowing whether a real
//     Keeper minted it. Another process holds no such entry, so a permit
//     replayed elsewhere opens nothing.
//   - Consume deletes and returns in one critical section, so two concurrent
//     display calls with the same challenge leave exactly one winner. A GCM tag
//     failure afterwards does not put the entry back — a retry starts from a
//     new prepare.
//   - Entries live 30 seconds, the same window the permit does, and are dropped
//     when their group handle closes and with the process. Nothing is persisted.
//
// The store holds no key material: a context, a digest over ciphertext, and a
// deadline. The secret it protects is the *right* to open one message once.

package handlers

import (
	"errors"
	"sync"
	"time"
)

const (
	// messageDisplayChallengeTTL — how long a minted challenge stays usable.
	// Matches the server's permit window (issued_at + 30) so neither side is the
	// looser one.
	//
	// Measured against Deps.Now, which is time.Now in production and therefore
	// carries a monotonic reading: the window survives a wall-clock adjustment
	// in either direction. Tests inject a clock to drive it deterministically.
	messageDisplayChallengeTTL = 30 * time.Second

	// messageDisplayMaxChallenges — live entries per process. A ninth concurrent
	// prepare is refused rather than evicting somebody else's pending reveal:
	// dropping the oldest entry would let a caller flush a challenge it does not
	// own, and turn a capacity limit into a denial-of-reveal.
	messageDisplayMaxChallenges = 8
)

// errMessageDisplayBusy is what Put returns when the map is full.
var errMessageDisplayBusy = errors.New("message display challenge capacity reached")

// messageDisplayContext is everything a prepare promised, remembered so the
// display step can check that the permit and the request still describe the
// same message.
//
// auditTableSlot holds the canonical rendering ("-" for a non-audit message),
// not a pointer: the slot is what the signature covers, and comparing slots
// keeps the "both absent" case from needing a second boolean.
type messageDisplayContext struct {
	groupHandle          string
	orgID                string
	groupID              string
	dekVersion           int
	messageSchemaVersion int
	tokenExpiresAt       int64
	auditTableSlot       string
	payloadSHA256        string
}

type messageDisplayEntry struct {
	context   messageDisplayContext
	expiresAt time.Time
}

// MessageChallengeStore is the per-process challenge map. App owns one and
// injects it through Deps, the way the session stores are injected, so parallel
// tests do not share entries.
//
// Every method tolerates a nil receiver and fails closed: a Deps built without
// a store cannot mint a challenge and cannot consume one, so the display action
// is simply unavailable rather than accidentally unguarded.
type MessageChallengeStore struct {
	mu      sync.Mutex
	entries map[string]messageDisplayEntry
}

func NewMessageChallengeStore() *MessageChallengeStore {
	return &MessageChallengeStore{entries: make(map[string]messageDisplayEntry)}
}

// Put registers a freshly minted challenge. Expired entries are swept first, so
// the capacity limit counts live reveals rather than abandoned ones.
func (s *MessageChallengeStore) Put(challenge string, context messageDisplayContext, now time.Time) error {
	if s == nil {
		return errMessageDisplayBusy
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked(now)
	if len(s.entries) >= messageDisplayMaxChallenges {
		return errMessageDisplayBusy
	}
	s.entries[challenge] = messageDisplayEntry{
		context:   context,
		expiresAt: now.Add(messageDisplayChallengeTTL),
	}
	return nil
}

// Peek returns the remembered context without consuming it, so the display step
// can check the permit against it before deciding to spend the challenge. An
// expired entry is evicted and reported as absent.
func (s *MessageChallengeStore) Peek(challenge string, now time.Time) (messageDisplayContext, bool) {
	if s == nil {
		return messageDisplayContext{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.entries[challenge]
	if !ok {
		return messageDisplayContext{}, false
	}
	if !now.Before(entry.expiresAt) {
		delete(s.entries, challenge)
		return messageDisplayContext{}, false
	}
	return entry.context, true
}

// Consume deletes the entry and returns it in one critical section. This is the
// single gate that makes a challenge one-shot: whichever caller wins the lock
// gets the context, everyone else gets false.
func (s *MessageChallengeStore) Consume(challenge string, now time.Time) (messageDisplayContext, bool) {
	if s == nil {
		return messageDisplayContext{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.entries[challenge]
	if !ok {
		return messageDisplayContext{}, false
	}
	delete(s.entries, challenge)
	if !now.Before(entry.expiresAt) {
		return messageDisplayContext{}, false
	}
	return entry.context, true
}

// PurgeHandle drops every challenge bound to a group handle. Called when the
// handle is closed: the key that would open those messages is gone, so the
// permission to open them should not outlive it.
//
// Keeper has no lock action — the other two ends of a challenge's life are its
// 30-second deadline and process exit, which takes the whole map with it.
func (s *MessageChallengeStore) PurgeHandle(groupHandle string) {
	if s == nil || groupHandle == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for challenge, entry := range s.entries {
		if entry.context.groupHandle == groupHandle {
			delete(s.entries, challenge)
		}
	}
}

// Len reports the live entry count. Testing / observability only; it does not
// sweep, so a test can observe that an expired entry is still resident before
// the next operation evicts it.
func (s *MessageChallengeStore) Len() int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries)
}

func (s *MessageChallengeStore) sweepLocked(now time.Time) {
	for challenge, entry := range s.entries {
		if !now.Before(entry.expiresAt) {
			delete(s.entries, challenge)
		}
	}
}
