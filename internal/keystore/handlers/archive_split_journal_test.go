package handlers

import (
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/testdouble"
)

const splitJournalPrefix = "archive_quorum_split_pending:"

var errInjectedStorage = errors.New("injected keychain failure")

// journalFaultStore fails the n-th write or delete of a split journal item
// (1-based; 0 never). With persist the failing call still takes effect, the
// way a keychain call that completed but reported an error does.
type journalFaultStore struct {
	keychain.SecretStore
	mu                   sync.Mutex
	sets, deletes        int
	failSet, failDel     int
	persist              bool
	afterFailSetsAllFail bool
}

func (s *journalFaultStore) Set(service, account, value string) error {
	if strings.HasPrefix(account, splitJournalPrefix) {
		s.mu.Lock()
		s.sets++
		fail := s.failSet != 0 && (s.sets == s.failSet || (s.afterFailSetsAllFail && s.sets > s.failSet))
		s.mu.Unlock()
		if fail {
			if s.persist {
				_ = s.SecretStore.Set(service, account, value)
			}
			return errInjectedStorage
		}
	}
	return s.SecretStore.Set(service, account, value)
}

func (s *journalFaultStore) Delete(service, account string) error {
	if strings.HasPrefix(account, splitJournalPrefix) {
		s.mu.Lock()
		s.deletes++
		fail := s.failDel != 0 && s.deletes == s.failDel
		s.mu.Unlock()
		if fail {
			if s.persist {
				_ = s.SecretStore.Delete(service, account)
			}
			return errInjectedStorage
		}
	}
	return s.SecretStore.Delete(service, account)
}

func (s *journalFaultStore) reset(failSet, failDel int, persist bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sets, s.deletes, s.failSet, s.failDel, s.persist = 0, 0, failSet, failDel, persist
}

// journalItems lists every split journal item in the fixture's store.
func journalItems(t *testing.T, f *splitFixture) []string {
	t.Helper()
	mem, ok := f.store.(*testdouble.MemorySecretStore)
	if !ok {
		t.Fatal("fixture store is not the in-memory store")
	}
	var items []string
	for key := range mem.Snapshot() {
		if _, account, _ := strings.Cut(key, "|"); strings.HasPrefix(account, splitJournalPrefix) {
			items = append(items, account)
		}
	}
	sort.Strings(items)
	return items
}

func splitKinds() []string { return []string{"activation", "reconfiguration"} }

// splitCase is one authorized split of either kind with its closure.
type splitCase struct {
	f    *splitFixture
	kind string
	req  proto.ArchiveKeySplitRequest
	slot keychain.ArchiveKeySlot
}

func newSplitCase(t *testing.T, kind string, recipients int) *splitCase {
	t.Helper()
	f := newSplitFixture(t)
	f.request.RecipientPublicKeys, f.request.RecipientAccountIDs = splitSizeRecipients(t, recipients)
	c := &splitCase{f: f, kind: kind}
	if kind == "reconfiguration" {
		c.req, _ = f.authorizeReconfiguration(t)
		c.slot = keychain.OrgArchiveReconfigurationSlot(f.v.OrgID)
	} else {
		c.slot = keychain.OrgArchiveActiveSlot(f.v.OrgID)
	}
	return c
}

// split runs a freshly authorized split of the case's request.
func (c *splitCase) split(t *testing.T) proto.BaseResponse {
	t.Helper()
	if c.kind == "reconfiguration" {
		// A reconfiguration decision is bound to the staged key; re-sign a
		// fresh one through the same path.
		f := c.f
		req := f.request
		req.Kind = "reconfiguration"
		req = f.authorize(t, req)
		d := req.Decision
		req.Decision = nil
		signed := *c.req.ReconfigurationDecision
		signed.Challenge, signed.RequestDigest, signed.IssuedAt, signed.ExpiresAt = d.Challenge, d.RequestDigest, d.IssuedAt, d.ExpiresAt
		canonical, err := signed.Canonical()
		if err != nil {
			t.Fatal(err)
		}
		signed.Signature = f.sign(t, canonical)
		req.ReconfigurationDecision = &signed
		return HandleArchiveKeySplit(f.deps, req)
	}
	return HandleArchiveKeySplit(c.f.deps, c.f.authorize(t, c.f.request))
}

// abandon closes the case's operation with a signed closure receipt.
func (c *splitCase) abandon(t *testing.T) proto.BaseResponse {
	t.Helper()
	f := c.f
	r := proto.ArchiveSplitClosureReceipt{OperationID: f.request.OperationID, OrgID: f.v.OrgID, Status: proto.ArchiveSplitClosedCancelled, ServerKeyVersion: 1}
	if c.kind == "reconfiguration" {
		d := c.req.ReconfigurationDecision
		r.Kind, r.SourceConfigDigest, r.TargetKeySPKIFingerprint = c.req.Kind, d.SourceConfigDigest, d.TargetKeySPKIFingerprint
	} else {
		r.ArchiveKeySPKIFingerprint = splitCaseSPKI(t, f)
	}
	r.Signature = f.sign(t, proto.ArchiveSplitClosureReceiptCanonical(r))
	return HandleArchiveSplitAbandon(f.deps, proto.ArchiveSplitAbandonRequest{OrgID: f.v.OrgID, Receipt: &r})
}

func splitCaseSPKI(t *testing.T, f *splitFixture) string {
	t.Helper()
	spki, err := crypto.RewrapKeyFingerprint(f.archive)
	if err != nil {
		t.Fatal(err)
	}
	return spki
}

func (c *splitCase) status(t *testing.T) proto.ArchiveSplitStateResponseData {
	t.Helper()
	r := HandleArchiveSplitStatus(c.f.deps, proto.ArchiveSplitStatusRequest{OrgID: c.f.v.OrgID})
	if !r.Success {
		t.Fatalf("status: %s %s", r.ErrorCode, r.Error)
	}
	return r.Data.(proto.ArchiveSplitStateResponseData)
}

// An interrupted split write, wherever it stops and whether or not the
// failing write took effect, never leaves an item that outlives the next
// split and its closure, and the next split of the same request succeeds.
func TestArchiveSplitInterruptedWriteLeavesNothingBehind(t *testing.T) {
	for _, kind := range splitKinds() {
		// A clean run counts the journal writes of one split.
		probe := newSplitCase(t, kind, 5)
		counter := &journalFaultStore{SecretStore: probe.f.deps.Store}
		probe.f.deps.Store = counter
		if r := probe.split(t); !r.Success {
			t.Fatalf("%s: clean split: %s", kind, r.ErrorCode)
		}
		writes := counter.sets
		for at := 1; at <= writes; at++ {
			for _, persist := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/write%d/persist=%v", kind, at, persist), func(t *testing.T) {
					c := newSplitCase(t, kind, 5)
					fault := &journalFaultStore{SecretStore: c.f.deps.Store, failSet: at, persist: persist, afterFailSetsAllFail: true}
					c.f.deps.Store = fault
					if r := c.split(t); r.Success || r.ErrorCode != string(errs.ErrCodeStorageFailure) {
						t.Fatalf("interrupted split answered %+v", r)
					}
					fault.reset(0, 0, false)
					first := c.split(t)
					if !first.Success {
						t.Fatalf("split after the interruption: %s %s", first.ErrorCode, first.Error)
					}
					if again := c.split(t); !again.Success || !reflect.DeepEqual(first.Data, again.Data) {
						t.Fatal("retry after the recovered split returned other shares")
					}
					if r := c.abandon(t); !r.Success {
						t.Fatalf("closure: %s %s", r.ErrorCode, r.Error)
					}
					if left := journalItems(t, c.f); len(left) != 0 {
						t.Fatalf("items left after closure: %v", left)
					}
				})
			}
		}
	}
}

// An activation split that stopped part way is never visible as a
// preparation, and a split of another operation with fewer parts followed by
// its closure leaves none of the first attempt's parts.
func TestArchiveSplitInterruptedWriteIsDiscardedByTheNextSplit(t *testing.T) {
	c := newSplitCase(t, "activation", 5)
	fault := &journalFaultStore{SecretStore: c.f.deps.Store, failSet: 5, afterFailSetsAllFail: true}
	c.f.deps.Store = fault
	if r := c.split(t); r.Success {
		t.Fatal("interrupted split succeeded")
	}
	fault.reset(0, 0, false)
	if s := c.status(t); s.State != proto.ArchiveSplitStateNone || s.OperationID != "" {
		t.Fatalf("status after an interrupted split = %+v", s)
	}
	c.f.request.OperationID = splitTestOther
	c.f.request.RecipientPublicKeys, c.f.request.RecipientAccountIDs = splitSizeRecipients(t, 2)
	first := c.split(t)
	if !first.Success {
		t.Fatalf("split of another operation: %s %s", first.ErrorCode, first.Error)
	}
	if again := c.split(t); !again.Success || !reflect.DeepEqual(first.Data, again.Data) {
		t.Fatal("retry of the other operation did not return its shares")
	}
	if r := c.abandon(t); !r.Success {
		t.Fatalf("closure: %s %s", r.ErrorCode, r.Error)
	}
	if left := journalItems(t, c.f); len(left) != 0 {
		t.Fatalf("items left after closure: %v", left)
	}
}

// A split that stopped part way is removed by the operation's closure,
// wherever the write stopped: for activation the record alone (the archive
// private key stays), for reconfiguration with the staged target.
func TestArchiveSplitInterruptedWriteIsRemovedByClosure(t *testing.T) {
	for _, kind := range splitKinds() {
		for at := 1; at <= 4; at++ {
			t.Run(fmt.Sprintf("%s/write%d", kind, at), func(t *testing.T) {
				c := newSplitCase(t, kind, 5)
				fault := &journalFaultStore{SecretStore: c.f.deps.Store, failSet: at, afterFailSetsAllFail: true}
				c.f.deps.Store = fault
				if r := c.split(t); r.Success {
					t.Fatal("interrupted split succeeded")
				}
				fault.reset(0, 0, false)
				written := len(journalItems(t, c.f)) > 0
				r := c.abandon(t)
				if kind == "activation" && !written {
					// Nothing was recorded, as before any split: no journal.
					if r.Success || r.ErrorCode != string(errs.ErrCodeNotFound) {
						t.Fatalf("closure without a record answered %+v", r)
					}
				} else if !r.Success {
					t.Fatalf("closure: %s %s", r.ErrorCode, r.Error)
				}
				if left := journalItems(t, c.f); len(left) != 0 {
					t.Fatalf("items left after closure: %v", left)
				}
				if kind == "activation" {
					if _, err := c.slot.GetPrivate(c.f.store); err != nil {
						t.Fatal("closure of an interrupted split removed the archive private key")
					}
				}
			})
		}
	}
}
