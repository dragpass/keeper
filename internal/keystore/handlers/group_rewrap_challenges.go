package handlers

import (
	"errors"
	"sync"
	"time"
)

const (
	groupRewrapChallengeTTL = time.Minute
	groupRewrapMaxPending   = 128
)

var errGroupRewrapBusy = errors.New("group rewrap challenge unavailable")

// groupRewrapContext contains only identities and digests. A signed decision
// must match this context and the live binding before any key operation.
type groupRewrapContext struct {
	accountID         string
	deviceID          string
	tokenID           string
	sessionStartNanos int64
	bindingGeneration uint64
	operation         string
	orgID             string
	groupID           string
	dekVersion        int
	sourceKind        string
	sourcePolicy      string
	outputPolicy      string
	sourceDigest      [32]byte
	requestDigest     [32]byte
	recipientsDigest  [32]byte
	groupHandle       string
}

type groupRewrapEntry struct {
	context   groupRewrapContext
	expiresAt time.Time
}

// GroupRewrapChallengeStore is process-local. Restart discards all pending
// challenges; Consume is atomic and one-shot even under concurrent callers.
type GroupRewrapChallengeStore struct {
	mu      sync.Mutex
	entries map[string]groupRewrapEntry
}

func NewGroupRewrapChallengeStore() *GroupRewrapChallengeStore {
	return &GroupRewrapChallengeStore{entries: make(map[string]groupRewrapEntry)}
}

func (s *GroupRewrapChallengeStore) Put(challenge string, context groupRewrapContext, now time.Time) error {
	if s == nil || challenge == "" {
		return errGroupRewrapBusy
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked(now)
	if len(s.entries) >= groupRewrapMaxPending {
		return errGroupRewrapBusy
	}
	if _, exists := s.entries[challenge]; exists {
		return errGroupRewrapBusy
	}
	s.entries[challenge] = groupRewrapEntry{context: context, expiresAt: now.Add(groupRewrapChallengeTTL)}
	return nil
}

func (s *GroupRewrapChallengeStore) Peek(challenge string, now time.Time) (groupRewrapContext, bool) {
	if s == nil {
		return groupRewrapContext{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.entries[challenge]
	if !ok {
		return groupRewrapContext{}, false
	}
	if !now.Before(entry.expiresAt) {
		delete(s.entries, challenge)
		return groupRewrapContext{}, false
	}
	return entry.context, true
}

func (s *GroupRewrapChallengeStore) Consume(challenge string, now time.Time) (groupRewrapContext, bool) {
	if s == nil {
		return groupRewrapContext{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.entries[challenge]
	if !ok {
		return groupRewrapContext{}, false
	}
	delete(s.entries, challenge)
	if !now.Before(entry.expiresAt) {
		return groupRewrapContext{}, false
	}
	return entry.context, true
}

func (s *GroupRewrapChallengeStore) PurgeHandle(handle string) {
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

func (s *GroupRewrapChallengeStore) Len() int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries)
}

func (s *GroupRewrapChallengeStore) sweepLocked(now time.Time) {
	for challenge, entry := range s.entries {
		if !now.Before(entry.expiresAt) {
			delete(s.entries, challenge)
		}
	}
}
