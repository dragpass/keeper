// archive_session_discard_test.go — the confirmed discard of one named key.
//
// The App calls archive_session_discard only after the user confirmed losing
// whatever recovery attempt a key belongs to. Keeper deletes the slot only
// when, read under the lock at the moment of the delete, its key has the
// named fingerprint; a key that took its place after the confirmation is
// refused and kept.

package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dragpass/keeper/config"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

func discardSession(deps Deps, orgID, fingerprint string) proto.BaseResponse {
	return HandleArchiveSessionDiscard(deps, proto.ArchiveSessionDiscardRequest{OrgID: orgID, Fingerprint: fingerprint, ConfirmDiscard: true})
}

func requireDiscarded(t *testing.T, resp proto.BaseResponse, want bool) {
	t.Helper()
	if !resp.Success || resp.Data.(proto.ArchiveSessionDiscardResponseData).Discarded != want {
		t.Fatalf("discard: success=%v code=%q data=%v, want discarded=%v", resp.Success, resp.ErrorCode, resp.Data, want)
	}
}

// A live session key is deleted with its index entry; the other
// organization's slot and the device-wide slot stay.
func TestArchiveSessionDiscard_DeletesOnlyTheConfirmedKey(t *testing.T) {
	deps, store, _ := newOrgSessionDeps(t)
	a := beginOrgSession(t, deps, testOrgA)
	beginOrgSession(t, deps, testOrgB)
	bValue := orgSlotValue(store, testOrgB)
	legacyPublic := saveLegacyDeviceSession(t, store)

	requireDiscarded(t, discardSession(deps, testOrgA, a.Fingerprint), true)
	requireOrgSlotGone(t, store, testOrgA)
	if slices.Contains(sessionIndexOrgs(t, store), testOrgA) || orgSlotValue(store, testOrgB) != bValue {
		t.Fatal("the discard left A's index entry or changed B")
	}
	if got, _ := store.Get(config.Service, config.LegacyOrgArchiveSessionPublicKey); got != legacyPublic {
		t.Fatal("the discard changed the device-wide slot")
	}
	requireDiscarded(t, discardSession(deps, testOrgA, a.Fingerprint), false)
}

// The user confirmed discarding key 1; before the request arrived key 1
// expired and a new session began. The discard is refused with
// archive_session_changed and the new key stays.
func TestArchiveSessionDiscard_RefusesWhenTheKeyChangedAfterConfirmation(t *testing.T) {
	deps, store, clock := newOrgSessionDeps(t)
	confirmed := beginOrgSession(t, deps, testOrgA)
	writeOrgSlotExpiry(t, store, testOrgA, clock.Now())
	fresh := beginOrgSession(t, deps, testOrgA)
	before := sessionSlotKeys(store)

	resp := discardSession(deps, testOrgA, confirmed.Fingerprint)
	if resp.Success || resp.ErrorCode != string(errs.ErrCodeArchiveSessionChanged) || resp.Data != nil {
		t.Fatalf("discard of a replaced key: success=%v code=%q", resp.Success, resp.ErrorCode)
	}
	if !reflect.DeepEqual(before, sessionSlotKeys(store)) || !archiveSessionFingerprintMatches(deps, testOrgA, fresh.Fingerprint) {
		t.Fatal("a refused discard changed the slot")
	}
}

// Untrusted slots are removed only this way, and only by their own
// fingerprint.
func TestArchiveSessionDiscard_RemovesAnUntrustedSlotByItsFingerprint(t *testing.T) {
	deps, store, clock := newOrgSessionDeps(t)
	a := beginOrgSession(t, deps, testOrgA)
	pristine := sessionSlotKeys(store)
	for name, write := range untrustedSlotRecords(t, store, clock, a) {
		t.Run(name, func(t *testing.T) {
			for k, v := range pristine {
				_ = store.Set(config.Service, strings.TrimPrefix(k, config.Service+"|"), v)
			}
			write()
			slotFP := a.Fingerprint
			if pub := orgSlotPublic(store, testOrgA); pub != "" {
				slotFP = fingerprintBase64Public(pub)
			}
			before := sessionSlotKeys(store)
			if resp := discardSession(deps, testOrgA, strings.Repeat("0", 64)); resp.ErrorCode != string(errs.ErrCodeArchiveSessionChanged) {
				t.Fatalf("discard by another fingerprint: %q", resp.ErrorCode)
			}
			if !reflect.DeepEqual(before, sessionSlotKeys(store)) {
				t.Fatal("a refused discard changed the slot")
			}
			requireDiscarded(t, discardSession(deps, testOrgA, slotFP), true)
			if orgSlotValue(store, testOrgA) != "" || orgSlotPublic(store, testOrgA) != "" {
				t.Fatal("the confirmed discard left the untrusted slot")
			}
		})
	}
}

// A private half with no public half and no v2 record (a development-build
// record whose public half is gone, bare or with the v1 header) has its
// fingerprint derived from the private key, in the same encoding begin
// uses. status reports it without writing anything, and only the confirmed
// discard naming it removes the slot; end, set_expiry and the sweeps leave
// it, and begin works once it is gone.
func TestArchiveSessionDiscard_RemovesASlotWithoutPublicHalfByItsDerivedFingerprint(t *testing.T) {
	for _, form := range []string{"bare key", "v1 record"} {
		t.Run(form, func(t *testing.T) {
			deps, mem, clock := newOrgSessionDeps(t)
			a := beginOrgSession(t, deps, testOrgA)
			value := orgSlotPEM(t, mem, testOrgA)
			if form == "v1 record" {
				value = sessionSlotHeaderForTest + strconv.FormatInt(clock.Now().Add(-time.Hour).Unix(), 10) + "\n" + value
			}
			writeOrgSlot(t, mem, testOrgA, value)
			_ = mem.Delete(config.Service, config.OrgArchiveSessionPublicKeyPrefix+testOrgA)
			before := mem.Snapshot()

			counting := &writeCountingStore{SecretStore: mem}
			d := deps
			d.Store = counting
			status := sessionStatus(t, d, testOrgA, a.Fingerprint)
			if status.State != proto.ArchiveSessionStateUnowned || status.Fingerprint != a.Fingerprint || status.StoredDigest != "" || !*status.FingerprintMatches {
				t.Fatalf("status: %+v", status)
			}
			if counting.writes.Load() != 0 {
				t.Fatal("status wrote")
			}
			if resp := HandleArchiveSessionEnd(deps, proto.ArchiveSessionEndRequest{OrgID: testOrgA, Fingerprint: a.Fingerprint}); !resp.Data.(proto.ArchiveSessionEndResponseData).SlotWithoutExpiryKept {
				t.Fatalf("end: %+v", resp.Data)
			}
			if resp := setExpiry(deps, testOrgA, a.Fingerprint, clock.Now().Add(time.Minute)); resp.ErrorCode != string(errs.ErrCodeArchiveSessionExpiryUnknown) {
				t.Fatalf("set_expiry: %q", resp.ErrorCode)
			}
			clock.Set(clock.Now().Add(48 * time.Hour))
			SweepExpiredArchiveSession(deps)
			if resp := discardSession(deps, testOrgA, strings.Repeat("0", 64)); resp.ErrorCode != string(errs.ErrCodeArchiveSessionChanged) {
				t.Fatalf("discard by another fingerprint: %q", resp.ErrorCode)
			}
			if !reflect.DeepEqual(before, mem.Snapshot()) {
				t.Fatal("something other than the confirmed discard changed the slot")
			}
			requireDiscarded(t, discardSession(deps, testOrgA, a.Fingerprint), true)
			requireOrgSlotGone(t, mem, testOrgA)
			beginOrgSession(t, deps, testOrgA)
		})
	}
}

// A private half that is not a key Keeper can parse, with no public half
// and no v2 record, has no fingerprint. status reports the digest of the
// stored bytes instead (stored_digest: hex(sha256(stored private record)),
// not a key fingerprint), and the confirmed discard naming that digest
// removes it. The digest is accepted for that shape only.
func TestArchiveSessionDiscard_RemovesAnUnparsableSlotByItsStoredDigest(t *testing.T) {
	deps, mem, _ := newOrgSessionDeps(t)
	a := beginOrgSession(t, deps, testOrgA)
	stored := "-----BEGIN PRIVATE KEY-----\nbm90IGEga2V5\n-----END PRIVATE KEY-----\n"
	writeOrgSlot(t, mem, testOrgA, stored)
	_ = mem.Delete(config.Service, config.OrgArchiveSessionPublicKeyPrefix+testOrgA)
	digest := sha256.Sum256([]byte(stored))
	want := hex.EncodeToString(digest[:])

	status := sessionStatus(t, deps, testOrgA, "")
	if status.State != proto.ArchiveSessionStateUnowned || status.Fingerprint != "" || status.StoredDigest != want {
		t.Fatalf("status: %+v", status)
	}
	before := mem.Snapshot()
	for _, req := range []proto.ArchiveSessionDiscardRequest{
		{OrgID: testOrgA, Fingerprint: a.Fingerprint, ConfirmDiscard: true},
		{OrgID: testOrgA, StoredDigest: strings.Repeat("0", 64), ConfirmDiscard: true},
	} {
		if resp := HandleArchiveSessionDiscard(deps, req); resp.ErrorCode != string(errs.ErrCodeArchiveSessionChanged) {
			t.Fatalf("discard %+v: %q", req, resp.ErrorCode)
		}
	}
	if !reflect.DeepEqual(before, mem.Snapshot()) {
		t.Fatal("a refused discard changed the slot")
	}
	requireDiscarded(t, HandleArchiveSessionDiscard(deps, proto.ArchiveSessionDiscardRequest{OrgID: testOrgA, StoredDigest: want, ConfirmDiscard: true}), true)
	requireOrgSlotGone(t, mem, testOrgA)

	// A slot that has a fingerprint is never discarded by a digest.
	beginOrgSession(t, deps, testOrgA)
	liveDigest := sha256.Sum256([]byte(orgSlotValue(mem, testOrgA)))
	if resp := HandleArchiveSessionDiscard(deps, proto.ArchiveSessionDiscardRequest{OrgID: testOrgA, StoredDigest: hex.EncodeToString(liveDigest[:]), ConfirmDiscard: true}); resp.ErrorCode != string(errs.ErrCodeArchiveSessionChanged) {
		t.Fatalf("digest discard of a slot with a fingerprint: %q", resp.ErrorCode)
	}
	if got := sessionStatus(t, deps, testOrgA, ""); got.StoredDigest != "" {
		t.Fatal("status reported a digest for a slot with a fingerprint")
	}
}

func TestArchiveSessionDiscard_Validates(t *testing.T) {
	deps, store, _ := newOrgSessionDeps(t)
	a := beginOrgSession(t, deps, testOrgA)
	before := store.Snapshot()
	for name, req := range map[string]proto.ArchiveSessionDiscardRequest{
		"no confirmation":          {OrgID: testOrgA, Fingerprint: a.Fingerprint},
		"no fingerprint or digest": {OrgID: testOrgA, ConfirmDiscard: true},
		"fingerprint and digest":   {OrgID: testOrgA, Fingerprint: a.Fingerprint, StoredDigest: a.Fingerprint, ConfirmDiscard: true},
		"uppercase digest":         {OrgID: testOrgA, StoredDigest: strings.ToUpper(a.Fingerprint), ConfirmDiscard: true},
		"no org_id":                {Fingerprint: a.Fingerprint, ConfirmDiscard: true},
	} {
		if resp := HandleArchiveSessionDiscard(deps, req); resp.ErrorCode != string(errs.ErrCodeValidation) {
			t.Fatalf("%s: %q", name, resp.ErrorCode)
		}
	}
	if !reflect.DeepEqual(before, store.Snapshot()) {
		t.Fatal("a refused discard changed the keychain")
	}
}

// A discard of the confirmed (expired) key races a new begin through one
// barrier: whichever runs first, the new key is never deleted.
func TestArchiveSessionDiscard_RacingABeginNeverDeletesTheNewKey(t *testing.T) {
	outcomes := map[string]int{}
	for round := range sessionRaceRounds * 2 {
		deps, store, clock := newOrgSessionDeps(t)
		confirmed := beginOrgSession(t, deps, testOrgA)
		writeOrgSlotExpiry(t, store, testOrgA, clock.Now())
		var discarded, fresh proto.BaseResponse
		raceActors(t,
			func() { discarded = discardSession(deps, testOrgA, confirmed.Fingerprint) },
			func() { fresh = beginOrgSessionResp(deps, testOrgA) },
		)
		if !fresh.Success {
			t.Fatalf("round %d: begin: %q", round, fresh.ErrorCode)
		}
		if !archiveSessionFingerprintMatches(deps, testOrgA, fresh.Data.(proto.ArchiveSessionBeginResponseData).Fingerprint) {
			t.Fatalf("round %d: the discard deleted the new key", round)
		}
		outcomes[discarded.ErrorCode+"/"+boolWord(discarded.Success)]++
	}
	t.Logf("discard outcomes: %v", outcomes)
}

func beginOrgSessionResp(deps Deps, orgID string) proto.BaseResponse {
	return HandleArchiveSessionBegin(deps, proto.ArchiveSessionBeginRequest{OrgID: orgID})
}

func boolWord(b bool) string {
	if b {
		return "ok"
	}
	return "refused"
}
