// archive_session_status_test.go — archive_session_status only reads.

package handlers

import (
	"reflect"
	"strings"
	"testing"

	"github.com/dragpass/keeper/config"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

func sessionStatus(t *testing.T, deps Deps, orgID, fingerprint string) proto.ArchiveSessionStatusResponseData {
	t.Helper()
	resp := HandleArchiveSessionStatus(deps, proto.ArchiveSessionStatusRequest{OrgID: orgID, Fingerprint: fingerprint})
	if !resp.Success {
		t.Fatalf("status: %q", resp.ErrorCode)
	}
	return resp.Data.(proto.ArchiveSessionStatusResponseData)
}

// Every state is reported without a single keychain write or delete: an
// expired slot is not deleted, an index entry without a slot is not
// dropped, an untrusted slot is not touched.
func TestArchiveSessionStatus_WritesNothingInAnyState(t *testing.T) {
	deps, mem, clock := newOrgSessionDeps(t)
	a := beginOrgSession(t, deps, testOrgA)
	untrusted := untrustedSlotRecords(t, mem, clock, a)
	pristine := mem.Snapshot()
	restore := func() {
		for k := range mem.Snapshot() {
			_ = mem.Delete(config.Service, strings.TrimPrefix(k, config.Service+"|"))
		}
		for k, v := range pristine {
			_ = mem.Set(config.Service, strings.TrimPrefix(k, config.Service+"|"), v)
		}
	}
	type want struct {
		state   string
		fp      string
		times   bool
		matches bool
	}
	cases := map[string]struct {
		setup func()
		want  want
	}{
		"live":    {func() {}, want{proto.ArchiveSessionStateLive, a.Fingerprint, true, true}},
		"expired": {func() { writeOrgSlotExpiry(t, mem, testOrgA, clock.Now()) }, want{proto.ArchiveSessionStateExpired, a.Fingerprint, true, true}},
		"absent with an index entry": {func() {
			_ = mem.Delete(config.Service, config.OrgArchiveSessionPrivateKeyPrefix+testOrgA)
		}, want{proto.ArchiveSessionStateAbsent, "", false, false}},
		"expiry unknown":              {untrusted["v2 beyond the expiry bound"], want{proto.ArchiveSessionStateExpiryUnknown, a.Fingerprint, false, true}},
		"unowned v1":                  {untrusted["v1 development record, live"], want{proto.ArchiveSessionStateUnowned, a.Fingerprint, false, true}},
		"unowned without public half": {untrusted["no header"], want{proto.ArchiveSessionStateUnowned, a.Fingerprint, false, true}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			restore()
			tc.setup()
			if name == "unowned without public half" {
				_ = mem.Delete(config.Service, config.OrgArchiveSessionPublicKeyPrefix+testOrgA)
				tc.want.fp, tc.want.matches = "", false
			}
			before := mem.Snapshot()
			counting := &writeCountingStore{SecretStore: mem}
			d := deps
			d.Store = counting
			got := sessionStatus(t, d, testOrgA, a.Fingerprint)
			if got.State != tc.want.state || got.Fingerprint != tc.want.fp || (got.ExpiresAt != "") != tc.want.times || (got.BegunAt != "") != tc.want.times {
				t.Fatalf("status: %+v", got)
			}
			if got.FingerprintMatches == nil || *got.FingerprintMatches != tc.want.matches {
				t.Fatalf("fingerprint_matches: %v", got.FingerprintMatches)
			}
			if counting.writes.Load() != 0 || !reflect.DeepEqual(before, mem.Snapshot()) {
				t.Fatalf("status wrote %d times", counting.writes.Load())
			}
		})
	}
}

// Without a fingerprint in the request, fingerprint_matches is absent; a
// foreign one is answered false. The device-wide slot is reported, not
// read as a session.
func TestArchiveSessionStatus_FingerprintAndDeviceWideSlot(t *testing.T) {
	deps, store, _ := newOrgSessionDeps(t)
	a := beginOrgSession(t, deps, testOrgA)
	if got := sessionStatus(t, deps, testOrgA, ""); got.FingerprintMatches != nil || got.Fingerprint != a.Fingerprint || got.LegacySlotPresent {
		t.Fatalf("status without fingerprint: %+v", got)
	}
	if got := sessionStatus(t, deps, testOrgA, strings.Repeat("0", 64)); got.FingerprintMatches == nil || *got.FingerprintMatches {
		t.Fatal("a foreign fingerprint matched")
	}
	legacyPublic := saveLegacyDeviceSession(t, store)
	got := sessionStatus(t, deps, testOrgB, fingerprintBase64Public(legacyPublic))
	if !got.LegacySlotPresent || got.State != proto.ArchiveSessionStateAbsent || *got.FingerprintMatches {
		t.Fatalf("status with the device-wide slot: %+v", got)
	}
}

func TestArchiveSessionStatus_Validates(t *testing.T) {
	deps, _, _ := newOrgSessionDeps(t)
	for name, req := range map[string]proto.ArchiveSessionStatusRequest{
		"no org_id":       {},
		"bad fingerprint": {OrgID: testOrgA, Fingerprint: "x"},
	} {
		if resp := HandleArchiveSessionStatus(deps, req); resp.ErrorCode != string(errs.ErrCodeValidation) {
			t.Fatalf("%s: %q", name, resp.ErrorCode)
		}
	}
}
