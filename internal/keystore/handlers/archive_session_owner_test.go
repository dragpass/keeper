package handlers

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

const ownerlessArchiveSessionHeader = "dragpass-archive-session-v2 "
const slotTestAccount = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"

func setSlotTestOwner(t *testing.T, d Deps, account string) {
	t.Helper()
	if _, err := keychain.GetPublicKey(d.Store); err == keychain.ErrSecretNotFound {
		if err := keychain.SavePublicKey(d.Store, "test account public key"); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := keychain.SetAccountBinding(d.Store, account, "test", true); err != nil {
		t.Fatal(err)
	}
}

func TestArchiveSessionOwnerChecksBeforeReplayStatusAndExpiry(t *testing.T) {
	d, store, clock := newOrgSessionDeps(t)
	setSlotTestOwner(t, d, slotTestAccount)
	req := proto.ArchiveSessionBeginRequest{OrgID: testOrgA, BeginID: "cccccccc-cccc-4ccc-8ccc-cccccccccccc"}
	r := HandleArchiveSessionBegin(d, req)
	if !r.Success {
		t.Fatal(r.ErrorCode)
	}
	fp := r.Data.(proto.ArchiveSessionBeginResponseData).Fingerprint
	setSlotTestOwner(t, d, "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
	before := store.Snapshot()
	for _, r := range []proto.BaseResponse{HandleArchiveSessionBegin(d, req), HandleArchiveSessionStatus(d, proto.ArchiveSessionStatusRequest{OrgID: testOrgA, Fingerprint: fp}), HandleArchiveSessionEnd(d, proto.ArchiveSessionEndRequest{OrgID: testOrgA, Fingerprint: fp}), discardSession(d, testOrgA, fp)} {
		if r.Success || r.ErrorCode != "archive_session_other_owner" || r.Data != nil {
			t.Fatal("expected opaque owner refusal, got", r.ErrorCode)
		}
	}
	clock.Set(clock.Now().Add(31 * time.Minute))
	if r := setExpiry(d, testOrgA, fp, clock.Now()); r.ErrorCode != "archive_session_other_owner" {
		t.Fatal(r.ErrorCode)
	}
	if !reflect.DeepEqual(before, store.Snapshot()) {
		t.Fatal("foreign request changed the store")
	}
	setSlotTestOwner(t, d, slotTestAccount)
	if r := HandleArchiveSessionBegin(d, req); r.Success {
		t.Fatal("old binding generation was reused")
	}
}

// Inner-combine fixtures supply an account explicitly in place of the signed decision gate.
func archiveQuorumCombineAndRewrap(d Deps, orgID string, req proto.ArchiveQuorumCombineAndRewrapRequest) proto.BaseResponse {
	b, _, _ := keychain.GetAccountBinding(d.Store)
	return combineArchiveForAccount(d, orgID, b.AccountID, req)
}

func TestArchiveSessionBeginBindsBothDecisionsToInitiatingOwner(t *testing.T) {
	d, store, _ := newOrgSessionDeps(t)
	var after map[string]string
	countKeygen(t, func() {
		setSlotTestOwner(t, d, "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
		if r := beginWithID(d, testOrgA, testBeginID1); !r.Success {
			t.Fatal("second account begin:", r.ErrorCode)
		}
		after = store.Snapshot()
	})
	r := beginWithID(d, testOrgA, testBeginID1)
	if r.Success || r.ErrorCode != "archive_session_login_unavailable" || r.Data != nil || !reflect.DeepEqual(after, store.Snapshot()) {
		t.Fatal("begin crossed its initiating account boundary")
	}
}

func assertUnknownOwnerPreserved(t *testing.T, d Deps, store interface{ Snapshot() map[string]string }, clock *orgSessionClock, fp string) {
	t.Helper()
	before := store.Snapshot()
	now := clock.Now()
	defer clock.Set(now)
	clock.Set(now.Add(24 * time.Hour))
	for _, r := range []proto.BaseResponse{
		beginWithID(d, testOrgA, testBeginID1),
		HandleArchiveSessionStatus(d, proto.ArchiveSessionStatusRequest{OrgID: testOrgA, Fingerprint: fp}),
		HandleArchiveSessionEnd(d, proto.ArchiveSessionEndRequest{OrgID: testOrgA, Fingerprint: fp}),
		setExpiry(d, testOrgA, fp, now), discardSession(d, testOrgA, fp),
		discardSession(d, testOrgA, strings.Repeat("0", 64)),
	} {
		if r.Success || r.ErrorCode != "archive_session_owner_unknown" || r.Data != nil {
			t.Fatal("ownerless slot response:", r.ErrorCode)
		}
	}
	SweepExpiredArchiveSession(d)
	if !reflect.DeepEqual(before, store.Snapshot()) {
		t.Fatal("ownerless record changed")
	}
}

func TestArchiveSessionV2PreservedEvenAfterConfirmedDiscard(t *testing.T) {
	d, store, clock := newOrgSessionDeps(t)
	a := beginOrgSession(t, d, testOrgA)
	header, pem, ok := strings.Cut(orgSlotValue(store, testOrgA), "\n")
	if !ok {
		t.Fatal("missing header")
	}
	header, _, ok = strings.Cut(header, " account=")
	if !ok {
		t.Fatal("missing account")
	}
	for _, h := range []string{strings.Replace(header, archiveSessionSlotHeader, ownerlessArchiveSessionHeader, 1), ownerlessArchiveSessionHeader + "expires_at=1"} {
		writeOrgSlot(t, store, testOrgA, h+"\n"+pem)
		assertUnknownOwnerPreserved(t, d, store, clock, a.Fingerprint)
	}
}

func TestArchiveAppLoginEndIsScopedToCapturedLogin(t *testing.T) {
	d, store, _ := newOrgSessionDeps(t)
	b, _, err := keychain.GetAccountBinding(store)
	if err != nil {
		t.Fatal(err)
	}
	req := proto.ArchiveAppLoginEndRequest{AccountID: b.AccountID, Generation: b.ChatStateGeneration}
	if r := HandleArchiveAppLoginEnd(d, req); !r.Success {
		t.Fatal(r.ErrorCode)
	}
	before := store.Snapshot()
	if r := HandleArchiveAppLoginEnd(d, req); !r.Success || !reflect.DeepEqual(before, store.Snapshot()) {
		t.Fatal("duplicated logout changed store")
	}
	if r := beginWithID(d, testOrgA, testBeginID1); r.Success || r.ErrorCode != "archive_session_login_unavailable" {
		t.Fatal("ended login admitted")
	}
	after, _, err := keychain.GetAccountBinding(store)
	if err != nil || after != b {
		t.Fatal("App logout changed device binding")
	}
	setSlotTestOwner(t, d, slotTestAccount)
	before = store.Snapshot()
	if r := HandleArchiveAppLoginEnd(d, req); !r.Success || !reflect.DeepEqual(before, store.Snapshot()) {
		t.Fatal("old logout changed newer login")
	}
	if r := beginWithID(d, testOrgA, testBeginID1); !r.Success {
		t.Fatal(r.ErrorCode)
	}
}

func TestArchiveEndIntentSettlesOnlyAfterCommitOrSupersession(t *testing.T) {
	d, store, _ := newOrgSessionDeps(t)
	id := "AAAAAAAAAAAAAAAAAAAAAA"
	other := "BBBBBBBBBBBBBBBBBBBBBA"
	sequence := uint64(0)
	end := proto.ArchiveAppLoginEndRequest{AccountID: slotTestAccount, IntentID: id, AfterSequence: &sequence}
	if r := HandleArchiveAppLoginEnd(d, end); r.Success {
		t.Fatal("unobserved intent settled")
	}
	if err := keychain.PrepareChatLogin(store, id, "", 0); err != nil {
		t.Fatal(err)
	}
	if r := HandleArchiveAppLoginEnd(d, end); r.Success {
		t.Fatal("pending intent settled")
	}
	if _, _, err := keychain.CommitChatLogin(store, id, slotTestAccount, "test"); err != nil {
		t.Fatal(err)
	}
	if r := HandleArchiveAppLoginEnd(d, end); !r.Success {
		t.Fatal(r.ErrorCode)
	}
	if r := beginWithID(d, testOrgA, testBeginID1); r.Success {
		t.Fatal("ended intent admitted")
	}
	state, err := keychain.ReadChatLogin(store)
	if err != nil {
		t.Fatal(err)
	}
	if err := keychain.PrepareChatLogin(store, other, state.Generation, state.PreparationSequence); err != nil {
		t.Fatal(err)
	}
	if _, _, err := keychain.CommitChatLogin(store, other, slotTestAccount, "test"); err != nil {
		t.Fatal(err)
	}
	before := store.Snapshot()
	if r := HandleArchiveAppLoginEnd(d, end); !r.Success || !reflect.DeepEqual(before, store.Snapshot()) {
		t.Fatal("superseded intent affected later login")
	}
}
