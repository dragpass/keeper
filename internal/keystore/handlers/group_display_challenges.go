package handlers

import (
	"errors"
	"sync"
	"time"
)

const (
	groupDisplayChallengeTTL  = 10 * time.Second
	groupDisplayMaxChallenges = 128
)

var errGroupDisplayBusy = errors.New("group display challenge unavailable")

// groupDisplayContext binds a server decision to the Keeper operation that
// minted its challenge. The store holds no plaintext or key material.
type groupDisplayContext struct {
	audit             bool
	auditTableID      string
	auditTableDigest  [32]byte
	groupHandle       string
	accountID         string
	deviceID          string
	tokenID           string
	sessionStartNanos int64
	bindingGeneration uint64
	operationDigest   [32]byte
	frameKeyDigest    [32]byte
}

type groupDisplayEntry struct {
	context   groupDisplayContext
	expiresAt time.Time
}

// GroupDisplayChallengeStore is process-local; restart, expiry and handle
// close discard an unused challenge. Consume is atomic and one-shot.
type GroupDisplayChallengeStore struct {
	mu      sync.Mutex
	entries map[string]groupDisplayEntry
}

func NewGroupDisplayChallengeStore() *GroupDisplayChallengeStore {
	return &GroupDisplayChallengeStore{entries: make(map[string]groupDisplayEntry)}
}

func (s *GroupDisplayChallengeStore) Put(challenge string, context groupDisplayContext, now time.Time) error {
	if s == nil || challenge == "" {
		return errGroupDisplayBusy
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked(now)
	if len(s.entries) >= groupDisplayMaxChallenges {
		return errGroupDisplayBusy
	}
	if _, exists := s.entries[challenge]; exists {
		return errGroupDisplayBusy
	}
	s.entries[challenge] = groupDisplayEntry{context: context, expiresAt: now.Add(groupDisplayChallengeTTL)}
	return nil
}

func (s *GroupDisplayChallengeStore) Peek(challenge string, now time.Time) (groupDisplayContext, bool) {
	if s == nil {
		return groupDisplayContext{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.entries[challenge]
	if !ok {
		return groupDisplayContext{}, false
	}
	if !now.Before(entry.expiresAt) {
		delete(s.entries, challenge)
		return groupDisplayContext{}, false
	}
	return entry.context, true
}

func (s *GroupDisplayChallengeStore) Consume(challenge string, now time.Time) (groupDisplayContext, bool) {
	if s == nil {
		return groupDisplayContext{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.entries[challenge]
	if !ok {
		return groupDisplayContext{}, false
	}
	delete(s.entries, challenge)
	if !now.Before(entry.expiresAt) {
		return groupDisplayContext{}, false
	}
	return entry.context, true
}

func (s *GroupDisplayChallengeStore) PurgeHandle(handle string) {
	if s == nil || handle == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for challenge, entry := range s.entries {
		if entry.context.groupHandle == handle {
			delete(s.entries, challenge)
		}
	}
}

func (s *GroupDisplayChallengeStore) Len() int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries)
}

func (s *GroupDisplayChallengeStore) sweepLocked(now time.Time) {
	for challenge, entry := range s.entries {
		if !now.Before(entry.expiresAt) {
			delete(s.entries, challenge)
		}
	}
}
