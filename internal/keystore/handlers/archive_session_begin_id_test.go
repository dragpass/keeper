// archive_session_begin_id_test.go — begin never replaces a live session,
// and a resend with the same begin_id gets the live session back.
//
// In this version a resend is matched on the organization and begin_id
// only. That is interim: the account condition comes with the account
// boundary change, and the owner step that will carry it already runs before
// the replay and the conflict branches (pinned below).

package handlers

import (
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

const (
	testBeginID1 = "11111111-aaaa-4aaa-8aaa-000000000001"
	testBeginID2 = "11111111-aaaa-4aaa-8aaa-000000000002"
)

// writeCountingStore counts writes and deletes.
type writeCountingStore struct {
	keychain.SecretStore
	writes atomic.Int32
}

func (s *writeCountingStore) Set(service, account, value string) error {
	s.writes.Add(1)
	return s.SecretStore.Set(service, account, value)
}

func (s *writeCountingStore) Delete(service, account string) error {
	s.writes.Add(1)
	return s.SecretStore.Delete(service, account)
}

func beginWithID(deps Deps, orgID, beginID string) proto.BaseResponse {
	return HandleArchiveSessionBegin(deps, proto.ArchiveSessionBeginRequest{OrgID: orgID, BeginID: beginID})
}

func requireActiveRefusal(t *testing.T, resp proto.BaseResponse, wantFP string) proto.ArchiveSessionActiveData {
	t.Helper()
	if resp.Success || resp.ErrorCode != string(errs.ErrCodeArchiveSessionActive) {
		t.Fatalf("want archive_session_active, got success=%v code=%q", resp.Success, resp.ErrorCode)
	}
	data := resp.Data.(proto.ArchiveSessionActiveData)
	if data.State != proto.ArchiveSessionStateLive || data.Fingerprint != wantFP || data.ExpiresAt == "" || data.BegunAt == "" {
		t.Fatalf("active data: %+v", data)
	}
	return data
}

// A begin with another begin_id, or none, over a live session is refused
// and the live key is kept and still combines.
func TestArchiveSessionBegin_LiveSessionRefusesAnotherBegin(t *testing.T) {
	deps, store, _ := newOrgSessionDeps(t)
	first := beginWithID(deps, testOrgA, testBeginID1).Data.(proto.ArchiveSessionBeginResponseData)
	before := sessionSlotKeys(store)
	for _, id := range []string{testBeginID2, ""} {
		data := requireActiveRefusal(t, beginWithID(deps, testOrgA, id), first.Fingerprint)
		if data.ExpiresAt != first.ExpiresAt || data.BegunAt != first.BegunAt {
			t.Fatalf("active data times: %+v", data)
		}
	}
	if !reflect.DeepEqual(before, sessionSlotKeys(store)) {
		t.Fatal("a refused begin changed the slot or the index")
	}
	req, member := sessionCombineRequest(t, testOrgA, first.SessionPublicKey, sessionTestDEK())
	assertMemberGrantOpens(t, archiveQuorumCombineAndRewrap(deps, testOrgA, req), member, sessionGrantContext(testOrgA), sessionTestDEK())
}

// Two begins without a begin_id: the second is refused, never replayed.
func TestArchiveSessionBegin_NoBeginIDNeverReplays(t *testing.T) {
	deps, _, _ := newOrgSessionDeps(t)
	first := beginWithID(deps, testOrgA, "").Data.(proto.ArchiveSessionBeginResponseData)
	requireActiveRefusal(t, beginWithID(deps, testOrgA, ""), first.Fingerprint)
}

// A resend with the same begin_id over the live session returns the same
// public key, fingerprint and begin time with the current (shortened)
// expiry, replayed true, and writes nothing.
func TestArchiveSessionBegin_SameBeginIDReplaysWithoutWriting(t *testing.T) {
	deps, mem, clock := newOrgSessionDeps(t)
	first := beginWithID(deps, testOrgA, testBeginID1).Data.(proto.ArchiveSessionBeginResponseData)
	if first.Replayed || first.BegunAt == "" {
		t.Fatalf("first begin: replayed=%v begun_at=%q", first.Replayed, first.BegunAt)
	}
	shortened := clock.Now().Add(10 * time.Minute)
	if resp := setExpiry(deps, testOrgA, first.Fingerprint, shortened); !resp.Success {
		t.Fatalf("set_expiry: %q", resp.ErrorCode)
	}
	clock.Set(clock.Now().Add(time.Minute))
	counting := &writeCountingStore{SecretStore: mem}
	deps.Store = counting
	before := sessionSlotKeys(mem)

	resp := beginWithID(deps, testOrgA, testBeginID1)
	if !resp.Success {
		t.Fatalf("resend: %q", resp.ErrorCode)
	}
	again := resp.Data.(proto.ArchiveSessionBeginResponseData)
	if !again.Replayed || again.SessionPublicKey != first.SessionPublicKey || again.Fingerprint != first.Fingerprint || again.BegunAt != first.BegunAt {
		t.Fatal("the resend did not return the live session")
	}
	if again.ExpiresAt != formatArchiveSessionExpiry(shortened) {
		t.Fatalf("resend expiry %s, want the current %s", again.ExpiresAt, formatArchiveSessionExpiry(shortened))
	}
	if n := counting.writes.Load(); n != 0 || !reflect.DeepEqual(before, sessionSlotKeys(mem)) {
		t.Fatalf("the resend wrote %d times", n)
	}
}

// The answer to a begin was lost: the App sends the same begin_id again and
// gets the session the first begin stored, whose key opens the shares.
func TestArchiveSessionBegin_LostResponseRetryReturnsTheSameSession(t *testing.T) {
	deps, _, _ := newOrgSessionDeps(t)
	_ = beginWithID(deps, testOrgA, testBeginID1) // the answer never reaches the App
	retry := beginWithID(deps, testOrgA, testBeginID1)
	if !retry.Success {
		t.Fatalf("retry: %q", retry.ErrorCode)
	}
	data := retry.Data.(proto.ArchiveSessionBeginResponseData)
	if !data.Replayed || !archiveSessionFingerprintMatches(deps, testOrgA, data.Fingerprint) {
		t.Fatal("the retry did not return the stored session")
	}
	req, member := sessionCombineRequest(t, testOrgA, data.SessionPublicKey, sessionTestDEK())
	assertMemberGrantOpens(t, archiveQuorumCombineAndRewrap(deps, testOrgA, req), member, sessionGrantContext(testOrgA), sessionTestDEK())
}

// Only a live session is replayed: once it has expired, a begin with the
// same begin_id starts a new session.
func TestArchiveSessionBegin_ExpiredSessionIsNotReplayed(t *testing.T) {
	deps, store, clock := newOrgSessionDeps(t)
	first := beginWithID(deps, testOrgA, testBeginID1).Data.(proto.ArchiveSessionBeginResponseData)
	writeOrgSlotExpiry(t, store, testOrgA, clock.Now())
	resp := beginWithID(deps, testOrgA, testBeginID1)
	if !resp.Success {
		t.Fatalf("begin after expiry: %q", resp.ErrorCode)
	}
	data := resp.Data.(proto.ArchiveSessionBeginResponseData)
	if data.Replayed || data.Fingerprint == first.Fingerprint {
		t.Fatal("an expired session was replayed")
	}
}

func TestArchiveSessionBegin_ValidatesBeginID(t *testing.T) {
	deps, mem, _ := newOrgSessionDeps(t)
	for _, id := range []string{"x", "11111111-AAAA-4AAA-8AAA-000000000001", "00000000-0000-0000-0000-000000000000"} {
		if resp := beginWithID(deps, testOrgA, id); resp.ErrorCode != string(errs.ErrCodeValidation) {
			t.Fatalf("begin_id %q: success=%v code=%q", id, resp.Success, resp.ErrorCode)
		}
	}
	if len(mem.Snapshot()) != 0 {
		t.Fatal("a refused begin wrote")
	}
}

// The owner step runs on the slot before the replay and the conflict
// branches. With a stub that refuses, a resend carrying the live session's
// begin_id gets the stub's refusal: no public key, fingerprint or time of
// the existing session, and nothing written. (This version's owner step
// admits every slot; the account boundary change fills it in.)
func TestArchiveSessionBegin_OwnerStepRunsBeforeReplayAndConflict(t *testing.T) {
	deps, mem, _ := newOrgSessionDeps(t)
	beginWithID(deps, testOrgA, testBeginID1)
	restore := archiveSessionOwnerRefusal
	t.Cleanup(func() { archiveSessionOwnerRefusal = restore })
	stub := proto.BaseResponse{Error: "stub owner refusal", ErrorCode: "stub_owner_refusal"}
	var judged []archiveSessionSlotState
	archiveSessionOwnerRefusal = func(_ Deps, _ string, slot archiveSessionSlot) (proto.BaseResponse, bool) {
		judged = append(judged, slot.state)
		return stub, true
	}
	counting := &writeCountingStore{SecretStore: mem}
	deps.Store = counting
	for _, id := range []string{testBeginID1, testBeginID2, ""} {
		resp := beginWithID(deps, testOrgA, id)
		if !reflect.DeepEqual(resp, stub) {
			t.Fatalf("begin_id %q answered %q with data %v", id, resp.ErrorCode, resp.Data != nil)
		}
	}
	if counting.writes.Load() != 0 {
		t.Fatal("a begin refused by the owner step wrote")
	}
	if len(judged) != 3 || judged[0] != archiveSessionSlotLive {
		t.Fatalf("owner step judged %v", judged)
	}
}
