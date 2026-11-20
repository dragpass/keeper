// archive_session_delete_failure_test.go — a slot is deleted all or
// reported.
//
// The private half goes first: once it is gone nothing usable is left. If
// it cannot be deleted, nothing else is touched, so the slot keeps its
// classification (trusted, still sweepable and endable) and the request
// answers storage_failure; the sweeps retry on their next run. If the
// public half or the index entry then fails, only a public half and an
// index entry remain: an absent slot that the next sweep finishes.

package handlers

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/dragpass/keeper/config"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// sessionDeleteFailingStore fails every Delete of an account with prefix while
// failing is set.
type sessionDeleteFailingStore struct {
	keychain.SecretStore
	prefix  string
	failing bool
}

func (s *sessionDeleteFailingStore) Delete(service, account string) error {
	if s.failing && strings.HasPrefix(account, s.prefix) {
		return errors.New("injected keychain delete failure")
	}
	return s.SecretStore.Delete(service, account)
}

type deleteFailureCaller struct {
	name string
	// expire makes the slot expired first (callers that delete on expiry).
	expire bool
	// run drives the caller once; the answer is checked when request is set.
	run     func(d Deps, a proto.ArchiveSessionBeginResponseData, req proto.ArchiveQuorumCombineAndRewrapRequest, clock *orgSessionClock) proto.BaseResponse
	request bool
}

func deleteFailureCallers() []deleteFailureCaller {
	return []deleteFailureCaller{
		{"end", false, func(d Deps, a proto.ArchiveSessionBeginResponseData, _ proto.ArchiveQuorumCombineAndRewrapRequest, _ *orgSessionClock) proto.BaseResponse {
			return HandleArchiveSessionEnd(d, proto.ArchiveSessionEndRequest{OrgID: testOrgA, Fingerprint: a.Fingerprint})
		}, true},
		{"discard", false, func(d Deps, a proto.ArchiveSessionBeginResponseData, _ proto.ArchiveQuorumCombineAndRewrapRequest, _ *orgSessionClock) proto.BaseResponse {
			return discardSession(d, testOrgA, a.Fingerprint)
		}, true},
		{"set_expiry on an expired slot", true, func(d Deps, a proto.ArchiveSessionBeginResponseData, _ proto.ArchiveQuorumCombineAndRewrapRequest, c *orgSessionClock) proto.BaseResponse {
			return setExpiry(d, testOrgA, a.Fingerprint, c.Now().Add(time.Minute))
		}, true},
		{"set_expiry to a passed time", false, func(d Deps, a proto.ArchiveSessionBeginResponseData, _ proto.ArchiveQuorumCombineAndRewrapRequest, c *orgSessionClock) proto.BaseResponse {
			return setExpiry(d, testOrgA, a.Fingerprint, c.Now().Add(-time.Minute))
		}, true},
		{"combine on an expired slot", true, func(d Deps, _ proto.ArchiveSessionBeginResponseData, req proto.ArchiveQuorumCombineAndRewrapRequest, _ *orgSessionClock) proto.BaseResponse {
			return archiveQuorumCombineAndRewrap(d, testOrgA, req)
		}, true},
		{"startup sweep", true, func(d Deps, _ proto.ArchiveSessionBeginResponseData, _ proto.ArchiveQuorumCombineAndRewrapRequest, _ *orgSessionClock) proto.BaseResponse {
			SweepExpiredArchiveSession(d)
			return proto.BaseResponse{}
		}, false},
		{"periodic sweep", true, func(d Deps, _ proto.ArchiveSessionBeginResponseData, _ proto.ArchiveQuorumCombineAndRewrapRequest, _ *orgSessionClock) proto.BaseResponse {
			ticks := make(chan time.Time)
			ctx, cancel := context.WithCancel(context.Background())
			stopped := make(chan struct{})
			go func() { defer close(stopped); RunArchiveSessionSweeper(ctx, d, ticks) }()
			ticks <- time.Time{}
			ticks <- time.Time{} // returns once the first tick's sweep finished
			cancel()
			<-stopped
			return proto.BaseResponse{}
		}, false},
	}
}

// The private half cannot be deleted: the caller answers storage_failure
// (a sweep logs and keeps going), the slot, its public half and its index
// entry are exactly as before, the slot is still judged the same, and the
// same caller succeeds once the keychain works again.
func TestArchiveSessionDelete_PrivateHalfFailureLeavesTheSlotIntact(t *testing.T) {
	for _, c := range deleteFailureCallers() {
		t.Run(c.name, func(t *testing.T) {
			deps, mem, clock := newOrgSessionDeps(t)
			a := beginOrgSession(t, deps, testOrgA)
			req, _ := sessionCombineRequest(t, testOrgA, a.SessionPublicKey, sessionTestDEK())
			if c.expire {
				clock.Set(clock.Now().Add(archiveSessionMaxTTL))
			}
			failing := &sessionDeleteFailingStore{SecretStore: mem, prefix: config.OrgArchiveSessionPrivateKeyPrefix + testOrgA, failing: true}
			d := deps
			d.Store = failing
			before := mem.Snapshot()

			resp := c.run(d, a, req, clock)
			if c.request && (resp.Success || resp.ErrorCode != string(errs.ErrCodeStorageFailure) || resp.Data != nil) {
				t.Fatalf("answer with a failing private delete: success=%v code=%q data=%v", resp.Success, resp.ErrorCode, resp.Data)
			}
			if !reflect.DeepEqual(before, mem.Snapshot()) {
				t.Fatalf("a failed private delete changed the keychain: %s", probeKeychainDiff(before, mem.Snapshot()))
			}
			status := sessionStatus(t, deps, testOrgA, "")
			wantState := proto.ArchiveSessionStateLive
			if c.expire {
				wantState = proto.ArchiveSessionStateExpired
			}
			if status.State != wantState || status.Fingerprint != a.Fingerprint {
				t.Fatalf("slot after the failure: %+v", status)
			}

			failing.failing = false
			retry := c.run(d, a, req, clock)
			if c.request && retry.ErrorCode == string(errs.ErrCodeStorageFailure) {
				t.Fatalf("retry: %q", retry.ErrorCode)
			}
			requireOrgSlotGone(t, mem, testOrgA)
			if slices.Contains(sessionIndexOrgs(t, mem), testOrgA) {
				t.Fatalf("index after the retry: %v", sessionIndexOrgs(t, mem))
			}
		})
	}
}

// The private half is deleted but the public half cannot be: the caller
// answers storage_failure, no private key is left, the public half and the
// index entry stay (an absent slot), and the next sweep removes both.
func TestArchiveSessionDelete_PublicHalfFailureLeavesNoPrivateKeyAndIsSwept(t *testing.T) {
	for _, c := range deleteFailureCallers() {
		t.Run(c.name, func(t *testing.T) {
			deps, mem, clock := newOrgSessionDeps(t)
			a := beginOrgSession(t, deps, testOrgA)
			req, _ := sessionCombineRequest(t, testOrgA, a.SessionPublicKey, sessionTestDEK())
			if c.expire {
				clock.Set(clock.Now().Add(archiveSessionMaxTTL))
			}
			failing := &sessionDeleteFailingStore{SecretStore: mem, prefix: config.OrgArchiveSessionPublicKeyPrefix + testOrgA, failing: true}
			d := deps
			d.Store = failing

			resp := c.run(d, a, req, clock)
			if c.request && (resp.Success || resp.ErrorCode != string(errs.ErrCodeStorageFailure)) {
				t.Fatalf("answer with a failing public delete: success=%v code=%q", resp.Success, resp.ErrorCode)
			}
			if orgSlotValue(mem, testOrgA) != "" || orgSlotPublic(mem, testOrgA) == "" || !slices.Contains(sessionIndexOrgs(t, mem), testOrgA) {
				t.Fatal("want no private half, the public half and the index entry")
			}
			if got := sessionStatus(t, deps, testOrgA, a.Fingerprint); got.State != proto.ArchiveSessionStateAbsent {
				t.Fatalf("status: %+v", got)
			}
			SweepExpiredArchiveSession(deps)
			requireOrgSlotGone(t, mem, testOrgA)
			if slices.Contains(sessionIndexOrgs(t, mem), testOrgA) {
				t.Fatal("the sweep left the index entry")
			}
		})
	}
}

func probeKeychainDiff(before, after map[string]string) string {
	var out []string
	for k, v := range before {
		if w, ok := after[k]; !ok {
			out = append(out, "deleted "+k)
		} else if w != v {
			out = append(out, "changed "+k)
		}
	}
	for k := range after {
		if _, ok := before[k]; !ok {
			out = append(out, "added "+k)
		}
	}
	slices.Sort(out)
	return strings.Join(out, ", ")
}
