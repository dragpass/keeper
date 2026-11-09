package handlers

import (
	"errors"
	"sync"
	"time"

	"github.com/dragpass/keeper/internal/keystore/proto"
)

const (
	archiveShareChallengeTTL = proto.ArchiveShareDecisionTTLSeconds * time.Second
	archiveShareMaxPending   = 128
)

var errArchiveShareBusy = errors.New("archive share challenge unavailable")

// archiveShareContext contains only identities and digests. A signed decision
// must match this context and the live binding before any key operation.
type archiveShareContext struct {
	accountID         string
	deviceID          string
	tokenID           string
	sessionStartNanos int64
	bindingGeneration uint64
	orgID             string
	recoverySessionID string
	// operationID and shareIndex bind split and share-open proof challenges
	// (lv86); they are empty or zero for share rewrap challenges.
	operationID   string
	shareIndex    int
	requestDigest string
}

type archiveShareEntry struct {
	context   archiveShareContext
	expiresAt time.Time
}

// ArchiveShareChallengeStore is process-local. Restart discards all pending
// challenges; Consume is atomic and one-shot even under concurrent callers.
type ArchiveShareChallengeStore struct {
	mu      sync.Mutex
	entries map[string]archiveShareEntry
}

func NewArchiveShareChallengeStore() *ArchiveShareChallengeStore {
	return &ArchiveShareChallengeStore{entries: make(map[string]archiveShareEntry)}
}

func (s *ArchiveShareChallengeStore) Put(challenge string, context archiveShareContext, now time.Time) error {
	if s == nil || challenge == "" {
		return errArchiveShareBusy
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked(now)
	if len(s.entries) >= archiveShareMaxPending {
		return errArchiveShareBusy
	}
	if _, exists := s.entries[challenge]; exists {
		return errArchiveShareBusy
	}
	s.entries[challenge] = archiveShareEntry{context: context, expiresAt: now.Add(archiveShareChallengeTTL)}
	return nil
}

func (s *ArchiveShareChallengeStore) Peek(challenge string, now time.Time) (archiveShareContext, bool) {
	entry, ok := s.peekEntry(challenge, now)
	return entry.context, ok
}

func (s *ArchiveShareChallengeStore) peekEntry(challenge string, now time.Time) (archiveShareEntry, bool) {
	if s == nil {
		return archiveShareEntry{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.entries[challenge]
	if !ok {
		return archiveShareEntry{}, false
	}
	if !now.Before(entry.expiresAt) {
		delete(s.entries, challenge)
		return archiveShareEntry{}, false
	}
	return entry, true
}

func (s *ArchiveShareChallengeStore) Consume(challenge string, now time.Time) (archiveShareContext, bool) {
	if s == nil {
		return archiveShareContext{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.entries[challenge]
	if !ok {
		return archiveShareContext{}, false
	}
	delete(s.entries, challenge)
	if !now.Before(entry.expiresAt) {
		return archiveShareContext{}, false
	}
	return entry.context, true
}

func (s *ArchiveShareChallengeStore) Len() int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries)
}

func (s *ArchiveShareChallengeStore) sweepLocked(now time.Time) {
	for challenge, entry := range s.entries {
		if !now.Before(entry.expiresAt) {
			delete(s.entries, challenge)
		}
	}
}
