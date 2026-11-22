package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/dragpass/keeper/config"
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
	return HandleArchiveKeySplit(c.f.deps, c.authorized(t))
}

// authorized returns the case's request carrying a fresh decision.
func (c *splitCase) authorized(t *testing.T) proto.ArchiveKeySplitRequest {
	t.Helper()
	f := c.f
	if c.kind != "reconfiguration" {
		return f.authorize(t, f.request)
	}
	// A reconfiguration decision is bound to the staged key; sign a fresh
	// one over the same facts.
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
	return req
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
	// The manifest and parts 0..5 are written: more parts than the next
	// operation's record has.
	fault := &journalFaultStore{SecretStore: c.f.deps.Store, failSet: 8, afterFailSetsAllFail: true}
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

// splitPart reads part i of the case's record.
func (c *splitCase) part(t *testing.T, i int) string {
	t.Helper()
	v, err := c.f.store.Get(config.Service, archiveSplitPartAccount(c.slot, i))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func (c *splitCase) setPart(t *testing.T, i int, v string) {
	t.Helper()
	if err := c.f.store.Set(config.Service, archiveSplitPartAccount(c.slot, i), v); err != nil {
		t.Fatal(err)
	}
}

// partFields splits a part into its header fields and data.
func partFields(t *testing.T, v string) []string {
	t.Helper()
	fields := strings.SplitN(v, "|", 7)
	if len(fields) != 7 {
		t.Fatalf("part format: %q", v[:min(len(v), 80)])
	}
	return fields
}

// A prepared record whose parts were mixed, edited, removed, added or
// reordered is never returned: the retry answers not_found and writes and
// deletes nothing, for both kinds.
func TestArchiveSplitRetryRefusesTamperedParts(t *testing.T) {
	other := newSplitCase(t, "activation", 5)
	other.f.request.OperationID = splitTestOther
	if r := other.split(t); !r.Success {
		t.Fatal(r.ErrorCode)
	}
	foreignPart := other.part(t, 0)
	tampers := map[string]func(t *testing.T, c *splitCase){
		"part of another operation": func(t *testing.T, c *splitCase) { c.setPart(t, 0, foreignPart) },
		"header names another operation": func(t *testing.T, c *splitCase) {
			f := partFields(t, c.part(t, 1))
			f[2] = splitTestOther
			c.setPart(t, 1, strings.Join(f, "|"))
		},
		"header names another whole digest": func(t *testing.T, c *splitCase) {
			f := partFields(t, c.part(t, 1))
			f[3] = strings.Repeat("ab", 32)
			c.setPart(t, 1, strings.Join(f, "|"))
		},
		"manifest names another whole digest": func(t *testing.T, c *splitCase) {
			j, _, err := loadArchiveSplitJournal(c.f.store, c.slot)
			if err != nil {
				t.Fatal(err)
			}
			j.ResultDigest = strings.Repeat("cd", 32)
			if err := writeArchiveSplitJournal(c.f.store, c.slot, j); err != nil {
				t.Fatal(err)
			}
		},
		"missing part": func(t *testing.T, c *splitCase) {
			if err := c.f.store.Delete(config.Service, archiveSplitPartAccount(c.slot, 1)); err != nil {
				t.Fatal(err)
			}
		},
		"extra part": func(t *testing.T, c *splitCase) {
			j, _, err := loadArchiveSplitJournal(c.f.store, c.slot)
			if err != nil {
				t.Fatal(err)
			}
			c.setPart(t, j.PartCount, encodeArchiveSplitPart(j.OperationID, j.ResultDigest, j.PartCount, j.PartCount, []byte("{}")))
		},
		"reordered parts": func(t *testing.T, c *splitCase) {
			p0, p1 := c.part(t, 0), c.part(t, 1)
			c.setPart(t, 0, p1)
			c.setPart(t, 1, p0)
		},
		"reordered data with renumbered headers": func(t *testing.T, c *splitCase) {
			f0, f1 := partFields(t, c.part(t, 0)), partFields(t, c.part(t, 1))
			f0[6], f1[6] = f1[6], f0[6]
			c.setPart(t, 0, strings.Join(f0, "|"))
			c.setPart(t, 1, strings.Join(f1, "|"))
		},
		"header index shifted": func(t *testing.T, c *splitCase) {
			f := partFields(t, c.part(t, 1))
			f[4] = "2"
			c.setPart(t, 1, strings.Join(f, "|"))
		},
		"header count changed": func(t *testing.T, c *splitCase) {
			f := partFields(t, c.part(t, 1))
			f[5] = "99"
			c.setPart(t, 1, strings.Join(f, "|"))
		},
		"truncated data": func(t *testing.T, c *splitCase) {
			v := c.part(t, 1)
			c.setPart(t, 1, v[:len(v)-1])
		},
	}
	for _, kind := range splitKinds() {
		for name, tamper := range tampers {
			t.Run(kind+"/"+name, func(t *testing.T) {
				c := newSplitCase(t, kind, 5)
				if r := c.split(t); !r.Success {
					t.Fatal(r.ErrorCode)
				}
				tamper(t, c)
				mem := c.f.store.(*testdouble.MemorySecretStore)
				before := mem.Snapshot()
				c.f.resetProbe()
				r := c.split(t)
				if r.Success || r.Data != nil || r.ErrorCode != string(errs.ErrCodeNotFound) {
					t.Fatalf("tampered record answered %+v", r)
				}
				if c.f.probe.sets != 0 || c.f.probe.deletes != 0 || !reflect.DeepEqual(before, mem.Snapshot()) {
					t.Fatal("refusal wrote or deleted an item")
				}
			})
		}
	}
}

// finalize sends the case's finalization receipt. A reconfiguration first
// needs the active private key gone, as after the grant rotation.
func (c *splitCase) finalize(t *testing.T, shares []proto.WrappedShare) proto.BaseResponse {
	t.Helper()
	f := c.f
	if c.kind == "reconfiguration" {
		if err := keychain.OrgArchiveActiveSlot(f.v.OrgID).DeletePrivate(f.store); err != nil && !errors.Is(err, keychain.ErrSecretNotFound) {
			t.Fatal(err)
		}
		d := c.req.ReconfigurationDecision
		r := proto.ArchiveSplitFinalizationReceipt{Kind: "reconfiguration", OperationID: c.req.OperationID, OrgID: c.req.OrgID, ArchiveKeySPKIFingerprint: d.ActiveKeySPKIFingerprint, TargetKeySPKIFingerprint: d.TargetKeySPKIFingerprint, SourceConfigDigest: d.SourceConfigDigest, ConfigDigest: d.ConfigDigest, SharesDigest: proto.ArchiveSplitSharesDigest(shares), GrantsDigest: strings.Repeat("f", 64), FinalizedAt: 500, ServerKeyVersion: 1}
		r.Signature = f.sign(t, proto.ArchiveSplitFinalizationReceiptCanonical(r))
		return HandleArchiveSplitFinalize(f.deps, proto.ArchiveSplitFinalizeRequest{OrgID: c.req.OrgID, Receipt: &r})
	}
	ff := &finalizeFixture{splitFixture: f, split: proto.ArchiveKeySplitResponseData{Shares: shares}, spki: splitCaseSPKI(t, f)}
	return HandleArchiveSplitFinalize(f.deps, ff.receipt(t, nil))
}

// checkPrefix fails unless the record's remaining parts are exactly 0..k-1
// and, when any part remains, its manifest is still there.
func (c *splitCase) checkPrefix(t *testing.T) {
	t.Helper()
	manifest := false
	indexes := map[int]bool{}
	for _, account := range journalItems(t, c.f) {
		if account == archiveSplitJournalAccount(c.slot) {
			manifest = true
			continue
		}
		_, index, ok := strings.Cut(account, ":part:")
		n, err := strconv.Atoi(index)
		if !ok || err != nil {
			t.Fatalf("unexpected journal item %s", account)
		}
		indexes[n] = true
	}
	for i := range len(indexes) {
		if !indexes[i] {
			t.Fatalf("remaining parts are not a prefix: %v", indexes)
		}
	}
	if len(indexes) > 0 && !manifest {
		t.Fatal("a part outlived its manifest")
	}
}

// A failed or interrupted delete at any position of finalization or closure,
// for both kinds, leaves a record the same receipt completes, never a part
// without its manifest, and never a record a split retry returns.
func TestArchiveSplitDeleteFailureAtEveryPositionResumes(t *testing.T) {
	type action struct {
		name    string
		run     func(t *testing.T, c *splitCase, shares []proto.WrappedShare) proto.BaseResponse
		failure map[string]string // kind -> error code of an incomplete delete
	}
	actions := []action{
		{"finalize", func(t *testing.T, c *splitCase, s []proto.WrappedShare) proto.BaseResponse { return c.finalize(t, s) },
			map[string]string{"activation": string(errs.ErrCodeArchiveSplitCleanupPending), "reconfiguration": string(errs.ErrCodeArchiveSplitCleanupPending)}},
		{"abandon", func(t *testing.T, c *splitCase, _ []proto.WrappedShare) proto.BaseResponse { return c.abandon(t) },
			map[string]string{"activation": string(errs.ErrCodeStorageFailure), "reconfiguration": string(errs.ErrCodeArchiveSplitCleanupPending)}},
	}
	for _, kind := range splitKinds() {
		for _, a := range actions {
			// 3 recipients: 5 parts and the manifest, 6 journal deletes.
			for at := 1; at <= 6; at++ {
				for _, persist := range []bool{false, true} {
					t.Run(fmt.Sprintf("%s/%s/delete%d/persist=%v", kind, a.name, at, persist), func(t *testing.T) {
						c := newSplitCase(t, kind, 3)
						split := c.split(t)
						if !split.Success {
							t.Fatal(split.ErrorCode)
						}
						shares := split.Data.(proto.ArchiveKeySplitResponseData).Shares
						if j, _, _ := loadArchiveSplitJournal(c.f.store, c.slot); j.PartCount+1 != 6 {
							t.Fatalf("fixture has %d parts", j.PartCount)
						}
						fault := &journalFaultStore{SecretStore: c.f.deps.Store, failDel: at, persist: persist}
						c.f.deps.Store = fault
						first := a.run(t, c, shares)
						c.checkPrefix(t)
						if !first.Success {
							if persist || first.ErrorCode != a.failure[kind] {
								t.Fatalf("failed delete answered %+v", first)
							}
							// A record that lost a part is never returned. One
							// whose first delete failed is still complete.
							if again := c.split(t); again.Success && len(journalItems(t, c.f)) < 6 {
								t.Fatal("split retry returned shares of a partly deleted record")
							}
							if kind == "activation" && a.name == "finalize" {
								if s := c.status(t); s.State != proto.ArchiveSplitStateCleanupPending {
									t.Fatalf("status after a failed delete = %+v", s)
								}
							}
						}
						fault.reset(0, 0, false)
						if r := a.run(t, c, shares); !first.Success && !r.Success {
							t.Fatalf("retry: %s %s", r.ErrorCode, r.Error)
						}
						if left := journalItems(t, c.f); len(left) != 0 {
							t.Fatalf("items left: %v", left)
						}
						_, err := c.slot.GetPrivate(c.f.store)
						if kept := err == nil; kept != (kind == "activation" && a.name == "abandon") {
							t.Fatalf("private key kept = %v after %s", kept, a.name)
						}
					})
				}
			}
		}
	}
}

// journalLockWatch records split journal and archive private slot accesses
// made while the fake keychain process lock was not held.
type journalLockWatch struct {
	keychain.SecretStore
	locked   *bool
	private  map[string]bool
	unlocked []string
}

func (s *journalLockWatch) note(op, account string) {
	if !*s.locked && (strings.HasPrefix(account, splitJournalPrefix) || s.private[account]) {
		s.unlocked = append(s.unlocked, op+" "+account)
	}
}

func (s *journalLockWatch) Get(service, account string) (string, error) {
	s.note("get", account)
	return s.SecretStore.Get(service, account)
}

func (s *journalLockWatch) Set(service, account, value string) error {
	s.note("set", account)
	return s.SecretStore.Set(service, account, value)
}

func (s *journalLockWatch) Delete(service, account string) error {
	s.note("delete", account)
	return s.SecretStore.Delete(service, account)
}

// Every read, write and delete of a split record and of the archive private
// key that split, status, finalization and closure make, for both kinds,
// runs while the keychain process lock is held, so a decision is never made
// from values another Keeper process changes in between.
func TestArchiveSplitJournalAccessHoldsTheProcessLock(t *testing.T) {
	type step struct {
		name string
		run  func(t *testing.T, c *splitCase, shares []proto.WrappedShare) proto.BaseResponse
	}
	status := func(t *testing.T, c *splitCase, _ []proto.WrappedShare) proto.BaseResponse {
		return HandleArchiveSplitStatus(c.f.deps, proto.ArchiveSplitStatusRequest{OrgID: c.f.v.OrgID})
	}
	for _, kind := range splitKinds() {
		for _, end := range []step{
			{"finalize", func(t *testing.T, c *splitCase, s []proto.WrappedShare) proto.BaseResponse { return c.finalize(t, s) }},
			{"abandon", func(t *testing.T, c *splitCase, _ []proto.WrappedShare) proto.BaseResponse { return c.abandon(t) }},
		} {
			t.Run(kind+"/"+end.name, func(t *testing.T) {
				c := newSplitCase(t, kind, 3)
				locked := false
				restore := archiveSlotProcessLock
				t.Cleanup(func() { archiveSlotProcessLock = restore })
				archiveSlotProcessLock = func(s keychain.SecretStore, fn func() error) error {
					return restore(s, func() error {
						locked = true
						defer func() { locked = false }()
						return fn()
					})
				}
				private := map[string]bool{c.slot.PrivateAccount: true}
				watch := &journalLockWatch{SecretStore: c.f.deps.Store, locked: &locked, private: private}
				c.f.deps.Store = watch
				split := c.split(t)
				if !split.Success {
					t.Fatal(split.ErrorCode)
				}
				shares := split.Data.(proto.ArchiveKeySplitResponseData).Shares
				for _, s := range []step{{"retry", func(t *testing.T, c *splitCase, _ []proto.WrappedShare) proto.BaseResponse { return c.split(t) }}, {"status", status}, end, {"status", status}} {
					if r := s.run(t, c, shares); !r.Success {
						t.Fatalf("%s: %s %s", s.name, r.ErrorCode, r.Error)
					}
				}
				if len(watch.unlocked) != 0 {
					t.Fatalf("accesses outside the process lock: %v", watch.unlocked)
				}
			})
		}
	}
}

// toLegacyRecord replaces the case's record with the single-item form that
// unreleased development builds wrote (the whole result in one item, no
// version field), with the given state.
func (c *splitCase) toLegacyRecord(t *testing.T, state string) {
	t.Helper()
	j, found, err := loadArchiveSplitJournal(c.f.store, c.slot)
	if err != nil || !found {
		t.Fatal("no record to convert", err)
	}
	result, err := readArchiveSplitResult(c.f.store, c.slot, j)
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := json.Marshal(map[string]any{
		"operation_id": j.OperationID, "request_digest": j.RequestDigest, "key_fingerprint": j.KeyFingerprint,
		"binding": j.Binding, "state": state, "result": result,
	})
	if err != nil {
		t.Fatal(err)
	}
	for i := range j.PartCount {
		if err := c.f.store.Delete(config.Service, archiveSplitPartAccount(c.slot, i)); err != nil {
			t.Fatal(err)
		}
	}
	setUnlimited(t, c.f.store, archiveSplitJournalAccount(c.slot), string(legacy))
}

// The single-item record of unreleased development builds is never returned
// or replaced by a split, and the existing signed actions still end it:
// status reports it, closure removes it and keeps the key, finalization
// removes it with the key, for both kinds.
func TestArchiveSplitLegacySingleItemRecord(t *testing.T) {
	for _, kind := range splitKinds() {
		t.Run(kind+"/split refuses", func(t *testing.T) {
			c := newSplitCase(t, kind, 2)
			if r := c.split(t); !r.Success {
				t.Fatal(r.ErrorCode)
			}
			c.toLegacyRecord(t, "")
			mem := c.f.store.(*testdouble.MemorySecretStore)
			before := mem.Snapshot()
			c.f.resetProbe()
			if r := c.split(t); r.Success || r.ErrorCode != string(errs.ErrCodeNotFound) {
				t.Fatalf("split over a legacy record answered %+v", r)
			}
			if c.f.probe.sets != 0 || c.f.probe.deletes != 0 || !reflect.DeepEqual(before, mem.Snapshot()) {
				t.Fatal("split changed a legacy record")
			}
			if kind == "activation" {
				if s := c.status(t); s.State != proto.ArchiveSplitStatePrepared || s.OperationID != c.f.request.OperationID {
					t.Fatalf("status of a legacy record = %+v", s)
				}
			}
		})
		t.Run(kind+"/closure removes it", func(t *testing.T) {
			c := newSplitCase(t, kind, 2)
			if r := c.split(t); !r.Success {
				t.Fatal(r.ErrorCode)
			}
			c.toLegacyRecord(t, "")
			if r := c.abandon(t); !r.Success {
				t.Fatalf("closure of a legacy record: %s %s", r.ErrorCode, r.Error)
			}
			if left := journalItems(t, c.f); len(left) != 0 {
				t.Fatalf("items left: %v", left)
			}
		})
		t.Run(kind+"/finalization removes it", func(t *testing.T) {
			c := newSplitCase(t, kind, 2)
			split := c.split(t)
			if !split.Success {
				t.Fatal(split.ErrorCode)
			}
			c.toLegacyRecord(t, "")
			shares := split.Data.(proto.ArchiveKeySplitResponseData).Shares
			wrong := append([]proto.WrappedShare(nil), shares...)
			wrong[0].ProofPublicKey = "AAAA"
			if r := c.finalize(t, wrong); r.Success {
				t.Fatal("finalization accepted another share set")
			}
			if r := c.finalize(t, shares); !r.Success {
				t.Fatalf("finalization of a legacy record: %s %s", r.ErrorCode, r.Error)
			}
			if left := journalItems(t, c.f); len(left) != 0 {
				t.Fatalf("items left: %v", left)
			}
		})
	}
	t.Run("activation/started deletion resumes", func(t *testing.T) {
		c := newSplitCase(t, "activation", 2)
		split := c.split(t)
		if !split.Success {
			t.Fatal(split.ErrorCode)
		}
		c.toLegacyRecord(t, archiveSplitJournalCleanupPending)
		if r := c.abandon(t); r.Success {
			t.Fatal("closure removed a legacy record whose deletion started")
		}
		if r := c.finalize(t, split.Data.(proto.ArchiveKeySplitResponseData).Shares); !r.Success {
			t.Fatalf("finalization: %s %s", r.ErrorCode, r.Error)
		}
		if left := journalItems(t, c.f); len(left) != 0 {
			t.Fatalf("items left: %v", left)
		}
	})
}

// setUnlimited writes a value past the platform limit, as only the Linux
// Secret Service backend (no limit in the library) could have stored it.
func setUnlimited(t *testing.T, store keychain.SecretStore, account, value string) {
	t.Helper()
	if err := store.Set(config.Service, account, value); err != nil {
		t.Fatal(err)
	}
}

const splitRaceRounds = 4

// Two splits of one operation released together write one record and return
// the same shares, for both kinds.
func TestArchiveSplitConcurrentSplitsOfOneOperationShareOneRecord(t *testing.T) {
	for _, kind := range splitKinds() {
		for round := range splitRaceRounds {
			t.Run(fmt.Sprintf("%s/%d", kind, round), func(t *testing.T) {
				c := newSplitCase(t, kind, 3)
				counter := &journalFaultStore{SecretStore: c.f.deps.Store}
				c.f.deps.Store = counter
				a, b := c.authorized(t), c.authorized(t)
				var ra, rb proto.BaseResponse
				raceActors(t,
					func() { ra = HandleArchiveKeySplit(c.f.deps, a) },
					func() { rb = HandleArchiveKeySplit(c.f.deps, b) },
				)
				if !ra.Success || !rb.Success || !reflect.DeepEqual(ra.Data, rb.Data) {
					t.Fatalf("concurrent splits: %+v / %+v", ra.ErrorCode, rb.ErrorCode)
				}
				j, _, err := loadArchiveSplitJournal(c.f.store, c.slot)
				if err != nil {
					t.Fatal(err)
				}
				// One record: the manifest twice (writing, prepared) and each part once.
				if counter.sets != j.PartCount+2 {
					t.Fatalf("%d journal writes for a %d-part record", counter.sets, j.PartCount)
				}
			})
		}
	}
}

// A split retry released together with the closure or the finalization of
// its operation ends in one serial outcome: the retry returns the original
// shares or is refused, the closing action completes, and no part of the
// record is left behind or mixed with a new one.
func TestArchiveSplitRetryRacingClosingActions(t *testing.T) {
	for _, kind := range splitKinds() {
		for _, closing := range []string{"abandon", "finalize"} {
			for round := range splitRaceRounds {
				t.Run(fmt.Sprintf("%s/%s/%d", kind, closing, round), func(t *testing.T) {
					c := newSplitCase(t, kind, 3)
					first := c.split(t)
					if !first.Success {
						t.Fatal(first.ErrorCode)
					}
					shares := first.Data.(proto.ArchiveKeySplitResponseData).Shares
					retryReq := c.authorized(t)
					var retry, end proto.BaseResponse
					raceActors(t,
						func() { retry = HandleArchiveKeySplit(c.f.deps, retryReq) },
						func() {
							if closing == "abandon" {
								end = c.abandon(t)
							} else {
								end = c.finalize(t, shares)
							}
						},
					)
					if !end.Success {
						t.Fatalf("%s: %s %s", closing, end.ErrorCode, end.Error)
					}
					items := journalItems(t, c.f)
					switch {
					case retry.Success && reflect.DeepEqual(retry.Data, first.Data):
						// The retry ran first; the closing action removed the record.
						if len(items) != 0 {
							t.Fatalf("items left: %v", items)
						}
					case retry.Success:
						// Only an activation closure leaves the key, so a split after
						// it may prepare anew; that record must be complete.
						if kind != "activation" || closing != "abandon" {
							t.Fatal("retry returned other shares")
						}
						j, found, err := loadArchiveSplitJournal(c.f.store, c.slot)
						if err != nil || !found || j.State != "" {
							t.Fatal("new preparation is not a complete record")
						}
						if got, err := readArchiveSplitResult(c.f.store, c.slot, j); err != nil || !reflect.DeepEqual(got, retry.Data) {
							t.Fatal("new preparation does not hold the returned shares")
						}
					default:
						if len(items) != 0 {
							t.Fatalf("items left after a refused retry: %v", items)
						}
					}
				})
			}
		}
	}
}
