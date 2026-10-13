// audit_authorizations.go — the process-local single-use record behind the
// audit actions' server-signed table receipts and decrypt permits.
//
// A receipt is keyed by its table id, so one shuffle table seals one token: a
// tampered Extension cannot stretch one recorded encryption over many tokens.
// A permit is keyed by its permit id, so one recorded disclosure opens one
// token once. An entry lives until its authorization would have expired
// anyway, then is swept.
//
// The record is in memory only (accepted: a Keeper restart inside a receipt's
// 60 seconds or a permit's 30 seconds forgets what it consumed, and another
// Keeper process never knew). It holds no key material.

package handlers

import (
	"errors"
	"sync"
	"time"
)

// auditAuthorizationCapacity bounds live entries. Every entry expires within a
// minute, so this is far above what one user's drags produce; reaching it
// refuses new audit operations rather than forgetting consumed ones.
const auditAuthorizationCapacity = 4096

var errAuditAuthorizationBusy = errors.New("audit authorization record is full")

// AuditAuthorizationStore remembers which receipts and permits this process
// has spent. A nil store fails closed: nothing can be consumed.
type AuditAuthorizationStore struct {
	mu       sync.Mutex
	consumed map[string]time.Time
}

func NewAuditAuthorizationStore() *AuditAuthorizationStore {
	return &AuditAuthorizationStore{consumed: make(map[string]time.Time)}
}

// Consume records key as spent until expiresAt. It reports false when key was
// already spent, and errAuditAuthorizationBusy when the record is full. The
// check and the write are one critical section, so concurrent callers with the
// same key leave exactly one winner.
func (s *AuditAuthorizationStore) Consume(key string, expiresAt, now time.Time) (bool, error) {
	if s == nil {
		return false, errAuditAuthorizationBusy
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, until := range s.consumed {
		if !now.Before(until) {
			delete(s.consumed, k)
		}
	}
	if _, spent := s.consumed[key]; spent {
		return false, nil
	}
	if len(s.consumed) >= auditAuthorizationCapacity {
		return false, errAuditAuthorizationBusy
	}
	s.consumed[key] = expiresAt
	return true, nil
}
