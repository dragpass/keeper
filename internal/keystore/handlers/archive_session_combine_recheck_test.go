// archive_session_combine_recheck_test.go — the combine checks the slot
// again, under the lock, right before it outputs.
//
// The combine reads the session key and releases the lock while it
// reassembles. Whatever another action did to the slot meanwhile decides
// the output: only the same record, still trusted and not expired now,
// lets the grants out. Each test runs the other action at exactly that
// point through archiveCombineBeforeOutputCheck, so the order is fixed
// without timing.

package handlers

import (
	"reflect"
	"testing"
	"time"

	"github.com/dragpass/keeper/config"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

func duringCombine(t *testing.T, action func()) {
	t.Helper()
	restore := archiveCombineBeforeOutputCheck
	t.Cleanup(func() { archiveCombineBeforeOutputCheck = restore })
	ran := false
	archiveCombineBeforeOutputCheck = func() {
		if !ran {
			ran = true
			action()
		}
	}
}

func requireCombineRefused(t *testing.T, resp proto.BaseResponse, code errs.ErrorCode) {
	t.Helper()
	if resp.Success || resp.Data != nil || resp.ErrorCode != string(code) {
		t.Fatalf("combine: success=%v code=%q data=%v, want %q and no output", resp.Success, resp.ErrorCode, resp.Data != nil, code)
	}
}

func TestArchiveCombineRecheck_UnchangedSlotOutputs(t *testing.T) {
	deps, _, _ := newOrgSessionDeps(t)
	a := beginOrgSession(t, deps, testOrgA)
	req, member := sessionCombineRequest(t, testOrgA, a.SessionPublicKey, sessionTestDEK())
	duringCombine(t, func() {
		_ = HandleArchiveSessionStatus(deps, proto.ArchiveSessionStatusRequest{OrgID: testOrgA})
	})
	assertMemberGrantOpens(t, archiveQuorumCombineAndRewrap(deps, testOrgA, req), member, sessionGrantContext(testOrgA), sessionTestDEK())
}

// set_expiry moves the expiry into the past while the combine runs: the
// slot is gone and no grant leaves.
func TestArchiveCombineRecheck_SetExpiryToThePastStopsTheOutput(t *testing.T) {
	deps, store, clock := newOrgSessionDeps(t)
	a := beginOrgSession(t, deps, testOrgA)
	req, _ := sessionCombineRequest(t, testOrgA, a.SessionPublicKey, sessionTestDEK())
	duringCombine(t, func() { setExpiry(deps, testOrgA, a.Fingerprint, clock.Now().Add(-time.Minute)) })
	requireCombineRefused(t, archiveQuorumCombineAndRewrap(deps, testOrgA, req), errs.ErrCodeNotFound)
	requireOrgSlotGone(t, store, testOrgA)
}

func TestArchiveCombineRecheck_EndStopsTheOutput(t *testing.T) {
	deps, _, _ := newOrgSessionDeps(t)
	a := beginOrgSession(t, deps, testOrgA)
	req, _ := sessionCombineRequest(t, testOrgA, a.SessionPublicKey, sessionTestDEK())
	duringCombine(t, func() {
		HandleArchiveSessionEnd(deps, proto.ArchiveSessionEndRequest{OrgID: testOrgA, Fingerprint: a.Fingerprint})
	})
	requireCombineRefused(t, archiveQuorumCombineAndRewrap(deps, testOrgA, req), errs.ErrCodeNotFound)
}

func TestArchiveCombineRecheck_ConfirmedDiscardStopsTheOutput(t *testing.T) {
	deps, _, _ := newOrgSessionDeps(t)
	a := beginOrgSession(t, deps, testOrgA)
	req, _ := sessionCombineRequest(t, testOrgA, a.SessionPublicKey, sessionTestDEK())
	duringCombine(t, func() { discardSession(deps, testOrgA, a.Fingerprint) })
	requireCombineRefused(t, archiveQuorumCombineAndRewrap(deps, testOrgA, req), errs.ErrCodeNotFound)
}

// The slot is discarded and a new session begins while the combine runs:
// no grant leaves under the old key, and the new key is left exactly as
// begin stored it.
func TestArchiveCombineRecheck_NewSessionAfterDiscardIsNeitherUsedNorTouched(t *testing.T) {
	deps, store, _ := newOrgSessionDeps(t)
	a := beginOrgSession(t, deps, testOrgA)
	req, _ := sessionCombineRequest(t, testOrgA, a.SessionPublicKey, sessionTestDEK())
	var fresh proto.ArchiveSessionBeginResponseData
	var after map[string]string
	duringCombine(t, func() {
		discardSession(deps, testOrgA, a.Fingerprint)
		fresh = beginOrgSession(t, deps, testOrgA)
		after = sessionSlotKeys(store)
	})
	requireCombineRefused(t, archiveQuorumCombineAndRewrap(deps, testOrgA, req), errs.ErrCodeNotFound)
	if !reflect.DeepEqual(after, sessionSlotKeys(store)) || !archiveSessionFingerprintMatches(deps, testOrgA, fresh.Fingerprint) {
		t.Fatal("the combine touched the new session")
	}
}

// The clock moves back while the combine runs (the same record now begins
// in the future): its expiry is no longer trusted, no grant leaves, and the
// slot is kept.
func TestArchiveCombineRecheck_UntrustedNowStopsTheOutputAndKeepsTheSlot(t *testing.T) {
	deps, store, clock := newOrgSessionDeps(t)
	a := beginOrgSession(t, deps, testOrgA)
	req, _ := sessionCombineRequest(t, testOrgA, a.SessionPublicKey, sessionTestDEK())
	before := sessionSlotKeys(store)
	duringCombine(t, func() { clock.Set(clock.Now().Add(-time.Hour)) })
	requireCombineRefused(t, archiveQuorumCombineAndRewrap(deps, testOrgA, req), errs.ErrCodeArchiveSessionExpiryUnknown)
	if !reflect.DeepEqual(before, sessionSlotKeys(store)) {
		t.Fatal("an untrusted slot was changed")
	}
}

// The slot expires while the combine runs and its delete fails: no output,
// storage_failure, the slot is intact (still expired, still sweepable), and
// the sweep then removes it.
func TestArchiveCombineRecheck_FailedExpiryDeleteIsReported(t *testing.T) {
	deps, mem, clock := newOrgSessionDeps(t)
	a := beginOrgSession(t, deps, testOrgA)
	req, _ := sessionCombineRequest(t, testOrgA, a.SessionPublicKey, sessionTestDEK())
	failing := &sessionDeleteFailingStore{SecretStore: mem, prefix: config.OrgArchiveSessionPrivateKeyPrefix + testOrgA}
	d := deps
	d.Store = failing
	var before map[string]string
	duringCombine(t, func() {
		clock.Set(clock.Now().Add(archiveSessionMaxTTL))
		failing.failing = true
		before = mem.Snapshot()
	})
	requireCombineRefused(t, archiveQuorumCombineAndRewrap(d, testOrgA, req), errs.ErrCodeStorageFailure)
	if !reflect.DeepEqual(before, mem.Snapshot()) {
		t.Fatal("a failed delete changed the keychain")
	}
	if got := sessionStatus(t, deps, testOrgA, a.Fingerprint); got.State != proto.ArchiveSessionStateExpired {
		t.Fatalf("slot after the failed delete: %q", got.State)
	}
	SweepExpiredArchiveSession(deps)
	requireOrgSlotGone(t, mem, testOrgA)
}
