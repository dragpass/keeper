// archive_session_trust_test.go — which session slots Keeper trusts.
//
// Only a record in this Keeper's format whose fingerprint matches the public
// half and whose expiry lies within the Keeper-side bound is used or deleted
// for being expired. Every other slot (a development-build record, no
// header, halves that disagree, an expiry beyond the bound) is refused for
// use and is never converted, replaced or deleted by begin, set_expiry,
// end, a combine or the startup sweep.

package handlers

import (
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dragpass/keeper/config"
	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// sessionSlotKeys returns every session account in the store.
func sessionSlotKeys(store interface{ Snapshot() map[string]string }) map[string]string {
	out := map[string]string{}
	for k, v := range store.Snapshot() {
		if strings.Contains(k, config.LegacyOrgArchiveSessionPrivateKey) || strings.Contains(k, config.LegacyOrgArchiveSessionPublicKey) || strings.Contains(k, config.OrgArchiveSessionIndex) {
			out[k] = v
		}
	}
	return out
}

// Begin writes the v3 owner-bound record: the expiry, the begin time, the fingerprint
// of the public half and the begin_id ("-" without one).
func TestArchiveSessionSlotRecordFormat(t *testing.T) {
	deps, store, clock := newOrgSessionDeps(t)
	a := beginOrgSession(t, deps, testOrgA)
	now := clock.Now().Unix()
	b, _, err := keychain.GetAccountBinding(store)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := keychain.GetPublicKey(store)
	if err != nil {
		t.Fatal(err)
	}
	want := archiveSessionSlotHeader + "expires_at=" + strconv.FormatInt(now+int64(archiveSessionMaxTTL/time.Second), 10) +
		" begun_at=" + strconv.FormatInt(now, 10) + " fp=" + a.Fingerprint + " begin_id=- account=" + b.AccountID + " generation=" + strconv.FormatUint(b.Generation, 10) + " account_fp=" + crypto.AccountKeyFingerprint([]byte(pub)) + "\n-----BEGIN"
	if got := orgSlotValue(store, testOrgA); !strings.HasPrefix(got, want) {
		t.Fatal("incorrect session header")
	}
	if fingerprintBase64Public(orgSlotPublic(store, testOrgA)) != a.Fingerprint {
		t.Fatal("the public half does not have the returned fingerprint")
	}
}

// untrustedSlotRecords are slots of org A, built from A's live session, that
// Keeper must not trust. Each entry writes the private and public halves.
func untrustedSlotRecords(t *testing.T, store keychain.SecretStore, clock *orgSessionClock, a proto.ArchiveSessionBeginResponseData) map[string]func() {
	t.Helper()
	pem := orgSlotPEM(t, store, testOrgA)
	public := orgSlotPublic(store, testOrgA)
	now := clock.Now()
	v1 := func(at time.Time) string {
		return sessionSlotHeaderForTest + strconv.FormatInt(at.Unix(), 10) + "\n" + pem
	}
	other, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	set := func(private, pub string) func() {
		return func() {
			writeOrgSlot(t, store, testOrgA, private)
			if pub == "" {
				_ = store.Delete(config.Service, config.OrgArchiveSessionPublicKeyPrefix+testOrgA)
			} else if err := store.Set(config.Service, config.OrgArchiveSessionPublicKeyPrefix+testOrgA, pub); err != nil {
				t.Fatal(err)
			}
		}
	}
	v2 := orgSlotValue(store, testOrgA)
	beyond := strings.Replace(v2, "expires_at="+strconv.FormatInt(now.Add(archiveSessionMaxTTL).Unix(), 10),
		"expires_at="+strconv.FormatInt(now.Add(archiveSessionMaxTTL).Unix()+1, 10), 1)
	return map[string]func(){
		"v1 development record, live":    set(v1(now.Add(time.Minute)), public),
		"v1 development record, expired": set(v1(now.Add(-time.Minute)), public),
		"no header":                      set(pem, public),

		"v2 with another public half":       set(v2, other.PublicKey),
		"v2 without its public half":        set(v2, ""),
		"v2 beyond the expiry bound":        set(beyond, public),
		"v2 expiring past begin plus bound": set(strings.Replace(v2, "begun_at="+strconv.FormatInt(now.Unix(), 10), "begun_at="+strconv.FormatInt(now.Add(-time.Hour).Unix(), 10), 1), public),
	}
}

// An untrusted slot is refused by begin as a conflict and by every use, and
// is left byte for byte by begin, set_expiry, end (with and without its
// fingerprint), a combine and the startup sweep, now and a day later.
func TestArchiveSessionUntrustedSlot_NeverReplacedUsedOrDeleted(t *testing.T) {
	deps, store, clock := newOrgSessionDeps(t)
	a := beginOrgSession(t, deps, testOrgA)
	req, _ := sessionCombineRequest(t, testOrgA, a.SessionPublicKey, sessionTestDEK())
	start := clock.Now()
	for name, write := range untrustedSlotRecords(t, store, clock, a) {
		t.Run(name, func(t *testing.T) {
			clock.Set(start)
			write()
			if name == "no header" || strings.HasPrefix(name, "v1 ") {
				assertUnknownOwnerPreserved(t, deps, store, clock, a.Fingerprint)
				return
			}
			before := sessionSlotKeys(store)
			begin := HandleArchiveSessionBegin(deps, proto.ArchiveSessionBeginRequest{OrgID: testOrgA})
			if begin.Success || begin.ErrorCode != string(errs.ErrCodeArchiveSessionActive) {
				t.Fatalf("begin over an untrusted slot: success=%v code=%q", begin.Success, begin.ErrorCode)
			}
			if state := begin.Data.(proto.ArchiveSessionActiveData).State; state == proto.ArchiveSessionStateLive {
				t.Fatalf("an untrusted slot reported as %q", state)
			}
			// set_expiry names the slot's own key (the public half's
			// fingerprint, or the record's without one), so it meets the
			// use rule rather than the fingerprint check.
			slotFP := a.Fingerprint
			if pub := orgSlotPublic(store, testOrgA); pub != "" {
				slotFP = fingerprintBase64Public(pub)
			}
			for use, resp := range map[string]proto.BaseResponse{
				"combine":    archiveQuorumCombineAndRewrap(deps, testOrgA, req),
				"set_expiry": setExpiry(deps, testOrgA, slotFP, start.Add(time.Minute)),
			} {
				if resp.Success || resp.ErrorCode != string(errs.ErrCodeArchiveSessionExpiryUnknown) {
					t.Fatalf("%s with an untrusted slot: success=%v code=%q", use, resp.Success, resp.ErrorCode)
				}
			}
			for _, end := range []proto.ArchiveSessionEndRequest{{OrgID: testOrgA, Fingerprint: a.Fingerprint}} {
				if resp := HandleArchiveSessionEnd(deps, end); !resp.Success || resp.Data.(proto.ArchiveSessionEndResponseData).Ended {
					t.Fatalf("end of an untrusted slot: success=%v data=%v", resp.Success, resp.Data)
				}
			}
			SweepExpiredArchiveSession(deps)
			clock.Set(start.Add(24 * time.Hour))
			SweepExpiredArchiveSession(deps)
			if resp := HandleArchiveSessionBegin(deps, proto.ArchiveSessionBeginRequest{OrgID: testOrgA}); resp.ErrorCode != string(errs.ErrCodeArchiveSessionActive) {
				t.Fatalf("begin a day later: success=%v code=%q", resp.Success, resp.ErrorCode)
			}
			if !reflect.DeepEqual(before, sessionSlotKeys(store)) {
				t.Fatal("an untrusted slot or the index was changed")
			}
		})
	}
}

// failingSessionStore fails the Set of one account.
type failingSessionStore struct {
	keychain.SecretStore
	failAccount string
}

func (s *failingSessionStore) Set(service, account, value string) error {
	if account == s.failAccount {
		return errors.New("injected keyring failure")
	}
	return s.SecretStore.Set(service, account, value)
}

// A begin that replaces an expired slot and fails before its private record
// is stored leaves no private record at all: never the new public half next
// to the old private key, which would be a slot no rule could trust.
func TestArchiveSessionBegin_InterruptedReplaceLeavesNoMixedHalves(t *testing.T) {
	deps, mem, clock := newOrgSessionDeps(t)
	beginOrgSession(t, deps, testOrgA)
	clock.Set(clock.Now().Add(archiveSessionMaxTTL))
	deps.Store = &failingSessionStore{SecretStore: mem, failAccount: config.OrgArchiveSessionPrivateKeyPrefix + testOrgA}
	if resp := HandleArchiveSessionBegin(deps, proto.ArchiveSessionBeginRequest{OrgID: testOrgA}); resp.Success {
		t.Fatal("begin succeeded with a failing keyring")
	}
	if orgSlotValue(mem, testOrgA) != "" {
		t.Fatal("the old private record survived next to a new public half")
	}
	deps.Store = mem
	if resp := HandleArchiveSessionBegin(deps, proto.ArchiveSessionBeginRequest{OrgID: testOrgA}); !resp.Success {
		t.Fatalf("begin after the interrupted one: code=%q", resp.ErrorCode)
	}
}

// set_expiry compares the fingerprint before anything else: a request
// naming another key is not_found and changes nothing, even when the slot
// has expired or is untrusted.
func TestArchiveSessionSetExpiry_ForeignFingerprintNeverCleansUp(t *testing.T) {
	foreign := strings.Repeat("0", 64)
	deps, store, clock := newOrgSessionDeps(t)
	a := beginOrgSession(t, deps, testOrgA)
	beginOrgSession(t, deps, testOrgB)

	writeOrgSlotExpiry(t, store, testOrgA, clock.Now())
	before := sessionSlotKeys(store)
	if resp := setExpiry(deps, testOrgA, foreign, clock.Now().Add(time.Minute)); resp.ErrorCode != string(errs.ErrCodeNotFound) {
		t.Fatalf("foreign fingerprint on an expired slot: success=%v code=%q", resp.Success, resp.ErrorCode)
	}
	if !reflect.DeepEqual(before, sessionSlotKeys(store)) {
		t.Fatal("a foreign fingerprint deleted an expired slot")
	}

	writeOrgSlot(t, store, testOrgA, orgSlotPEM(t, store, testOrgA))
	before = sessionSlotKeys(store)
	if resp := setExpiry(deps, testOrgA, foreign, clock.Now().Add(time.Minute)); resp.ErrorCode != "archive_session_owner_unknown" {
		t.Fatalf("foreign fingerprint on an untrusted slot: success=%v code=%q", resp.Success, resp.ErrorCode)
	}
	if !reflect.DeepEqual(before, sessionSlotKeys(store)) {
		t.Fatal("a foreign fingerprint changed an untrusted slot")
	}
	// Its own fingerprint still meets the use rule.
	if resp := setExpiry(deps, testOrgA, a.Fingerprint, clock.Now().Add(time.Minute)); resp.ErrorCode != "archive_session_owner_unknown" {
		t.Fatalf("own fingerprint on an untrusted slot: %q", resp.ErrorCode)
	}
}

// archive_session_end names the key it ends. The org_id-only form, which
// ended whatever the slot held, is refused with validation_error and changes
// nothing; an end of an earlier key leaves a newer session in place.
func TestArchiveSessionEnd_RequiresTheFingerprintOfTheKeyItEnds(t *testing.T) {
	deps, store, clock := newOrgSessionDeps(t)
	old := beginOrgSession(t, deps, testOrgA)
	before := sessionSlotKeys(store)
	if resp := HandleArchiveSessionEnd(deps, proto.ArchiveSessionEndRequest{OrgID: testOrgA}); resp.ErrorCode != string(errs.ErrCodeValidation) {
		t.Fatalf("org_id-only end: success=%v code=%q", resp.Success, resp.ErrorCode)
	}
	if !reflect.DeepEqual(before, sessionSlotKeys(store)) {
		t.Fatal("an org_id-only end changed the slot")
	}

	writeOrgSlotExpiry(t, store, testOrgA, clock.Now())
	fresh := beginOrgSession(t, deps, testOrgA)
	late := HandleArchiveSessionEnd(deps, proto.ArchiveSessionEndRequest{OrgID: testOrgA, Fingerprint: old.Fingerprint})
	if !late.Success || late.Data.(proto.ArchiveSessionEndResponseData).Ended || !archiveSessionFingerprintMatches(deps, testOrgA, fresh.Fingerprint) {
		t.Fatal("a late end of the earlier key removed the newer session")
	}
}

// v2 records whose fields contradict each other or are not written the way
// Keeper writes them are not trusted, so no rule ever deletes them for being
// expired: an expiry before the begin, a begin later than Keeper's clock,
// numbers that are not canonical decimal.
func TestArchiveSessionSlot_InconsistentRecordsAreUntrusted(t *testing.T) {
	deps, store, clock := newOrgSessionDeps(t)
	a := beginOrgSession(t, deps, testOrgA)
	v2 := orgSlotValue(store, testOrgA)
	now := clock.Now()
	_, suffix, found := strings.Cut(v2, " fp=")
	if !found {
		t.Fatal("missing fingerprint in test record")
	}
	record := func(expires, begun string) string {
		return archiveSessionSlotHeader + "expires_at=" + expires + " begun_at=" + begun + " fp=" + suffix
	}
	unix := func(t time.Time) string { return strconv.FormatInt(t.Unix(), 10) }
	// sweepAt is when the sweep runs. A begin later than the clock is a
	// clock that moved back: once the clock passes the begin the record is
	// consistent again and its expiry is trusted, as with the expiry bound,
	// so that case is swept while the clock is still behind.
	for name, tc := range map[string]struct {
		value   string
		state   string
		sweepAt time.Time
	}{
		"expiry before begin":        {record(unix(now.Add(-2*time.Hour)), unix(now.Add(-time.Hour))), proto.ArchiveSessionStateExpiryUnknown, now.Add(24 * time.Hour)},
		"begin later than the clock": {record(unix(now.Add(10*time.Minute)), unix(now.Add(time.Minute))), proto.ArchiveSessionStateExpiryUnknown, now},
		"leading plus":               {record("+"+unix(now.Add(-time.Hour)), unix(now.Add(-time.Hour-time.Minute))), proto.ArchiveSessionStateUnowned, now.Add(24 * time.Hour)},
		"leading zero":               {record("0"+unix(now.Add(-time.Hour)), unix(now.Add(-time.Hour-time.Minute))), proto.ArchiveSessionStateUnowned, now.Add(24 * time.Hour)},
	} {
		t.Run(name, func(t *testing.T) {
			clock.Set(now)
			writeOrgSlot(t, store, testOrgA, tc.value)
			if tc.state == proto.ArchiveSessionStateUnowned {
				assertUnknownOwnerPreserved(t, deps, store, clock, a.Fingerprint)
				return
			}
			if got := sessionStatus(t, deps, testOrgA, ""); got.State != tc.state {
				t.Fatalf("state %q, want %q", got.State, tc.state)
			}
			before := sessionSlotKeys(store)
			if resp := setExpiry(deps, testOrgA, a.Fingerprint, now.Add(time.Minute)); resp.ErrorCode != string(errs.ErrCodeArchiveSessionExpiryUnknown) {
				t.Fatalf("set_expiry: %q", resp.ErrorCode)
			}
			if resp := HandleArchiveSessionBegin(deps, proto.ArchiveSessionBeginRequest{OrgID: testOrgA}); resp.ErrorCode != string(errs.ErrCodeArchiveSessionActive) {
				t.Fatalf("begin: %q", resp.ErrorCode)
			}
			clock.Set(tc.sweepAt)
			SweepExpiredArchiveSession(deps)
			if !reflect.DeepEqual(before, sessionSlotKeys(store)) {
				t.Fatal("an inconsistent record was changed or deleted")
			}
		})
	}
	clock.Set(now)
	writeOrgSlot(t, store, testOrgA, v2)
}

// The header fingerprint matches the public half but the private PEM is
// another key (only possible by editing the keychain). Keeper does not
// parse the private key to classify the slot, so it reads as live; the
// combine still fails closed: the shares do not open, nothing is output.
func TestArchiveSessionCombine_PrivateKeyNotMatchingThePublicHalfFailsClosed(t *testing.T) {
	deps, store, _ := newOrgSessionDeps(t)
	a := beginOrgSession(t, deps, testOrgA)
	other, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	value := orgSlotValue(store, testOrgA)
	header := value[:strings.Index(value, "\n")+1]
	writeOrgSlot(t, store, testOrgA, header+other.PrivateKey)
	req, _ := sessionCombineRequest(t, testOrgA, a.SessionPublicKey, sessionTestDEK())
	resp := archiveQuorumCombineAndRewrap(deps, testOrgA, req)
	if resp.Success || resp.Data != nil || resp.ErrorCode != string(errs.ErrCodeCryptoFailure) {
		t.Fatalf("combine with a swapped private key: success=%v code=%q", resp.Success, resp.ErrorCode)
	}
}
