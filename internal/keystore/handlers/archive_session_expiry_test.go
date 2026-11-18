package handlers

import (
	"strings"
	"testing"
	"time"

	"github.com/dragpass/keeper/config"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// The per-organization record header development builds of lv90 K0 and
// lv100 F1 wrote, and the device-wide record of a main build of lv100 F1.
// This Keeper reads such a record as unowned. Tests write it literally so
// they pin that it is never trusted.
const sessionSlotHeaderForTest = "dragpass-archive-session-v1 expires_at="

// rewriteSessionSlotExpiry rewrites the expiry of the v2 record in account,
// keeping every other field, the way set_expiry would store it, and returns
// the new value.
func rewriteSessionSlotExpiry(t *testing.T, store keychain.SecretStore, account string, expiresAt time.Time) string {
	t.Helper()
	value, err := store.Get(config.Service, account)
	if err != nil {
		t.Fatal(err)
	}
	rec, pem, ok := decodeArchiveSessionSlot(value)
	if !ok {
		t.Fatal("the slot does not hold a v2 record")
	}
	rec.expiresAt = expiresAt
	buf := encodeArchiveSessionSlot(rec, []byte(pem))
	defer buf.Destroy()
	next := string(buf.Bytes())
	if err := store.Set(config.Service, account, next); err != nil {
		t.Fatal(err)
	}
	return next
}

// sessionExpiryOrg is the organization whose session slot the lv100 F1 tests
// exercise. authorizedCombineFixture and newAuditFixture begin their session
// for the fixture organization (f.v.OrgID), the same one.
const sessionExpiryOrg = "22222222-2222-4222-8222-222222222222"

func sessionSlotPEM(t *testing.T, store keychain.SecretStore) string {
	t.Helper()
	value, err := store.Get(config.Service, config.OrgArchiveSessionPrivateKeyPrefix+sessionExpiryOrg)
	if err != nil || value == "" {
		t.Fatal("no session slot")
	}
	start := strings.Index(value, "-----BEGIN")
	if start < 0 {
		t.Fatal("session slot holds no PEM")
	}
	return value[start:]
}

// writeSessionSlotWithoutExpiry rewrites the slot the way a Keeper before
// lv100 F1 stored it: the bare private key PEM.
func writeSessionSlotWithoutExpiry(t *testing.T, store keychain.SecretStore) string {
	t.Helper()
	pem := sessionSlotPEM(t, store)
	if err := store.Set(config.Service, config.OrgArchiveSessionPrivateKeyPrefix+sessionExpiryOrg, pem); err != nil {
		t.Fatal(err)
	}
	return pem
}

func writeSessionSlotExpiry(t *testing.T, store keychain.SecretStore, expiresAt int64) string {
	t.Helper()
	return rewriteSessionSlotExpiry(t, store, config.OrgArchiveSessionPrivateKeyPrefix+sessionExpiryOrg, time.Unix(expiresAt, 0))
}

func sessionSlotValue(store keychain.SecretStore, account string) string {
	value, _ := store.Get(config.Service, account)
	return value
}

func requireSessionSlotDeleted(t *testing.T, store keychain.SecretStore) {
	t.Helper()
	if sessionSlotValue(store, config.OrgArchiveSessionPrivateKeyPrefix+sessionExpiryOrg) != "" || sessionSlotValue(store, config.OrgArchiveSessionPublicKeyPrefix+sessionExpiryOrg) != "" {
		t.Fatal("expired session slot was not deleted")
	}
}

func TestArchiveCombineRefusesExpiredSessionSlotAndDeletesIt(t *testing.T) {
	f, req := authorizedCombineFixture(t)
	writeSessionSlotExpiry(t, f.store, f.clock.now().Unix())

	response := HandleArchiveQuorumCombineAndRewrap(f.deps, req)
	if response.Success || response.Data != nil || response.ErrorCode != "archive_session_expired" {
		t.Fatalf("expired session slot was used: success=%v code=%s", response.Success, response.ErrorCode)
	}
	requireSessionSlotDeleted(t, f.store)
}

func TestArchiveCombineRefusesSessionSlotWithoutExpiryAndKeepsIt(t *testing.T) {
	f, req := authorizedCombineFixture(t)
	legacy := writeSessionSlotWithoutExpiry(t, f.store)

	response := HandleArchiveQuorumCombineAndRewrap(f.deps, req)
	if response.Success || response.Data != nil || response.ErrorCode != "archive_session_expiry_unknown" {
		t.Fatalf("session slot without expiry was used: success=%v code=%s", response.Success, response.ErrorCode)
	}
	if sessionSlotValue(f.store, config.OrgArchiveSessionPrivateKeyPrefix+sessionExpiryOrg) != legacy {
		t.Fatal("session slot without expiry was changed or deleted by a use")
	}
}

// A record whose expiry lies further ahead than any session this Keeper
// starts (a clock moved back, or a value not written by begin) is not trusted.
func TestArchiveCombineRefusesSessionSlotBeyondUpperBound(t *testing.T) {
	f, req := authorizedCombineFixture(t)
	value := writeSessionSlotExpiry(t, f.store, f.clock.now().Add(archiveSessionMaxTTL).Unix()+1)

	response := HandleArchiveQuorumCombineAndRewrap(f.deps, req)
	if response.Success || response.ErrorCode != "archive_session_expiry_unknown" {
		t.Fatalf("slot beyond the upper bound was used: success=%v code=%s", response.Success, response.ErrorCode)
	}
	if sessionSlotValue(f.store, config.OrgArchiveSessionPrivateKeyPrefix+sessionExpiryOrg) != value {
		t.Fatal("slot beyond the upper bound was changed")
	}
}

// The decision in the fixture lives ten seconds, so the session's own upper
// bound is exercised below the decision check.
func TestArchiveSessionBeginBoundsTheSlotLifetime(t *testing.T) {
	f, req := authorizedCombineFixture(t)
	begun := f.clock.now()

	f.clock.unix = begun.Add(archiveSessionMaxTTL - time.Second).Unix()
	if live := archiveQuorumCombineAndRewrap(f.deps, sessionExpiryOrg, req); !live.Success {
		t.Fatalf("session refused before its upper bound: %s", live.ErrorCode)
	}

	f.clock.unix = begun.Add(archiveSessionMaxTTL).Unix()
	expired := archiveQuorumCombineAndRewrap(f.deps, sessionExpiryOrg, req)
	if expired.Success || expired.ErrorCode != "archive_session_expired" {
		t.Fatalf("session used at its upper bound: success=%v code=%s", expired.Success, expired.ErrorCode)
	}
	requireSessionSlotDeleted(t, f.store)
}

// The slot never outlives the server session when the App never reports the
// server expiry: ariadne's session lives 30 minutes from its open, which
// follows begin, so a 30-minute bound from begin ends no later.
func TestArchiveSessionUpperBoundIsNoLaterThanTheServerSessionLifetime(t *testing.T) {
	if archiveSessionMaxTTL > 30*time.Minute || archiveSessionMaxTTL < 10*time.Minute {
		t.Fatalf("archiveSessionMaxTTL = %s", archiveSessionMaxTTL)
	}
}

// The reconstruction can outlast the slot: output is withheld and the slot
// deleted when its expiry passes before the combine returns.
func TestArchiveCombineWithholdsOutputWhenTheSlotExpiresDuringIt(t *testing.T) {
	f, req := authorizedCombineFixture(t)
	begun := f.clock.now()
	read := false
	f.deps.Store = &combinePrivateReadProbe{SecretStore: f.store, beforeRead: func() { read = true }}
	calls := 0
	f.deps.Clock = func() time.Time {
		if read {
			calls++
			if calls > 1 {
				return begun.Add(archiveSessionMaxTTL)
			}
		}
		return begun
	}

	response := archiveQuorumCombineAndRewrap(f.deps, sessionExpiryOrg, req)
	if response.Success || response.Data != nil || response.ErrorCode != "archive_session_expired" {
		t.Fatalf("output after the slot expired: success=%v code=%s", response.Success, response.ErrorCode)
	}
	if calls < 2 {
		t.Fatal("the expiry was not checked again after the reconstruction")
	}
	requireSessionSlotDeleted(t, f.store)
}

// slotReadHook runs hook the first time the session private key is read.
type slotReadHook struct {
	keychain.SecretStore
	hook func()
}

func (s *slotReadHook) Get(service, account string) (string, error) {
	value, err := s.SecretStore.Get(service, account)
	if account == config.OrgArchiveSessionPrivateKeyPrefix+sessionExpiryOrg && s.hook != nil {
		hook := s.hook
		s.hook = nil
		hook()
	}
	return value, err
}

// A begin in another process can write a new session between the sweep's
// read of an expired slot and its delete. The sweep must not delete the new
// session: begin's write and the sweep's read-check-delete are serialized.
func TestArchiveSessionStartupSweepKeepsASessionBegunDuringIt(t *testing.T) {
	f := newAuditFixture(t)
	beginForExpiry(t, f)
	writeSessionSlotExpiry(t, f.store, f.clock.now().Unix())

	probe := &slotReadHook{SecretStore: f.store}
	deps := f.deps
	deps.Store = probe
	var fresh proto.ArchiveSessionBeginResponseData
	done := make(chan struct{})
	probe.hook = func() {
		go func() {
			defer close(done)
			begun := HandleArchiveSessionBegin(f.deps, proto.ArchiveSessionBeginRequest{OrgID: sessionExpiryOrg})
			if begun.Success {
				fresh = begun.Data.(proto.ArchiveSessionBeginResponseData)
			}
		}()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
		}
	}

	SweepExpiredArchiveSession(deps)
	<-done
	if fresh.Fingerprint == "" {
		t.Fatal("concurrent begin failed")
	}
	if sessionSlotValue(f.store, config.OrgArchiveSessionPrivateKeyPrefix+sessionExpiryOrg) == "" || !archiveSessionFingerprintMatches(f.deps, sessionExpiryOrg, fresh.Fingerprint) {
		t.Fatal("the startup sweep deleted a session begun while it ran")
	}
}

func beginForExpiry(t *testing.T, f *auditFixture) proto.ArchiveSessionBeginResponseData {
	t.Helper()
	if f.v.OrgID != sessionExpiryOrg {
		t.Fatalf("fixture organization %s, want %s", f.v.OrgID, sessionExpiryOrg)
	}
	// The fixture already began one session; begin again so the test holds
	// the response.
	begun := HandleArchiveSessionBegin(f.deps, proto.ArchiveSessionBeginRequest{OrgID: sessionExpiryOrg})
	if !begun.Success {
		t.Fatal("begin failed")
	}
	return begun.Data.(proto.ArchiveSessionBeginResponseData)
}

func TestArchiveSessionBeginReportsItsUpperBound(t *testing.T) {
	f := newAuditFixture(t)
	data := beginForExpiry(t, f)
	want := f.clock.now().Add(archiveSessionMaxTTL).UTC().Format(time.RFC3339)
	if data.ExpiresAt != want {
		t.Fatalf("begin expires_at = %q, want %q", data.ExpiresAt, want)
	}
}

func TestArchiveSessionSetExpiryOnlyShortens(t *testing.T) {
	f := newAuditFixture(t)
	data := beginForExpiry(t, f)
	now := f.clock.now()

	later := HandleArchiveSessionSetExpiry(f.deps, proto.ArchiveSessionSetExpiryRequest{
		OrgID: sessionExpiryOrg, Fingerprint: data.Fingerprint, ExpiresAt: now.Add(2 * time.Hour).UTC().Format(time.RFC3339),
	})
	if !later.Success {
		t.Fatalf("set expiry refused: %s", later.ErrorCode)
	}
	if got := later.Data.(proto.ArchiveSessionSetExpiryResponseData).ExpiresAt; got != data.ExpiresAt {
		t.Fatalf("a later server expiry extended the slot to %s", got)
	}

	sooner := now.Add(10 * time.Minute).UTC().Format(time.RFC3339)
	shortened := HandleArchiveSessionSetExpiry(f.deps, proto.ArchiveSessionSetExpiryRequest{OrgID: sessionExpiryOrg, Fingerprint: data.Fingerprint, ExpiresAt: sooner})
	if !shortened.Success || shortened.Data.(proto.ArchiveSessionSetExpiryResponseData).ExpiresAt != sooner {
		t.Fatalf("server expiry not applied: %+v", shortened)
	}

	f.clock.unix = now.Add(10 * time.Minute).Unix()
	again := HandleArchiveSessionSetExpiry(f.deps, proto.ArchiveSessionSetExpiryRequest{OrgID: sessionExpiryOrg, Fingerprint: data.Fingerprint, ExpiresAt: sooner})
	if again.Success || again.ErrorCode != "archive_session_expired" {
		t.Fatalf("slot used at the server expiry: success=%v code=%s", again.Success, again.ErrorCode)
	}
	requireSessionSlotDeleted(t, f.store)
}

func TestArchiveSessionSetExpiryRefusesAnotherSessionsFingerprint(t *testing.T) {
	f := newAuditFixture(t)
	beginForExpiry(t, f)
	before := sessionSlotValue(f.store, config.OrgArchiveSessionPrivateKeyPrefix+sessionExpiryOrg)

	response := HandleArchiveSessionSetExpiry(f.deps, proto.ArchiveSessionSetExpiryRequest{
		OrgID: sessionExpiryOrg, Fingerprint: strings.Repeat("0", 64), ExpiresAt: f.clock.now().Add(time.Minute).UTC().Format(time.RFC3339),
	})
	if response.Success || response.ErrorCode != "not_found" {
		t.Fatalf("expiry applied to another session: success=%v code=%s", response.Success, response.ErrorCode)
	}
	if sessionSlotValue(f.store, config.OrgArchiveSessionPrivateKeyPrefix+sessionExpiryOrg) != before {
		t.Fatal("refused set expiry changed the slot")
	}
}

func TestArchiveSessionSetExpiryInThePastDeletesTheSlot(t *testing.T) {
	f := newAuditFixture(t)
	data := beginForExpiry(t, f)

	response := HandleArchiveSessionSetExpiry(f.deps, proto.ArchiveSessionSetExpiryRequest{
		OrgID: sessionExpiryOrg, Fingerprint: data.Fingerprint, ExpiresAt: f.clock.now().UTC().Format(time.RFC3339),
	})
	if response.Success || response.ErrorCode != "archive_session_expired" {
		t.Fatalf("past server expiry accepted: success=%v code=%s", response.Success, response.ErrorCode)
	}
	requireSessionSlotDeleted(t, f.store)
}

func TestArchiveSessionSetExpiryKeepsASlotWithoutExpiry(t *testing.T) {
	f := newAuditFixture(t)
	data := beginForExpiry(t, f)
	legacy := writeSessionSlotWithoutExpiry(t, f.store)

	response := HandleArchiveSessionSetExpiry(f.deps, proto.ArchiveSessionSetExpiryRequest{
		OrgID: sessionExpiryOrg, Fingerprint: data.Fingerprint, ExpiresAt: f.clock.now().Add(time.Minute).UTC().Format(time.RFC3339),
	})
	if response.Success || response.ErrorCode != "archive_session_expiry_unknown" {
		t.Fatalf("slot without expiry accepted an expiry: success=%v code=%s", response.Success, response.ErrorCode)
	}
	if sessionSlotValue(f.store, config.OrgArchiveSessionPrivateKeyPrefix+sessionExpiryOrg) != legacy {
		t.Fatal("slot without expiry changed")
	}
}

func TestArchiveSessionSetExpiryValidates(t *testing.T) {
	for name, req := range map[string]proto.ArchiveSessionSetExpiryRequest{
		"no fingerprint": {OrgID: sessionExpiryOrg, ExpiresAt: "2026-11-16T00:00:00Z"},
		"no expiry":      {OrgID: sessionExpiryOrg, Fingerprint: strings.Repeat("a", 64)},
		"bad expiry":     {OrgID: sessionExpiryOrg, Fingerprint: strings.Repeat("a", 64), ExpiresAt: "tomorrow"},
		"no org_id":      {Fingerprint: strings.Repeat("a", 64), ExpiresAt: "2026-11-16T00:00:00Z"},
		"bad org_id":     {OrgID: "x", Fingerprint: strings.Repeat("a", 64), ExpiresAt: "2026-11-16T00:00:00Z"},
	} {
		if err := req.Validate(); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	if err := (proto.ArchiveSessionSetExpiryRequest{OrgID: sessionExpiryOrg, Fingerprint: strings.Repeat("a", 64), ExpiresAt: "2026-11-16T00:00:00Z"}).Validate(); err != nil {
		t.Fatalf("a complete request refused: %v", err)
	}
}

func TestArchiveSessionEndWithAnotherSessionsFingerprintKeepsTheSlot(t *testing.T) {
	f := newAuditFixture(t)
	beginForExpiry(t, f)
	before := sessionSlotValue(f.store, config.OrgArchiveSessionPrivateKeyPrefix+sessionExpiryOrg)

	end := HandleArchiveSessionEnd(f.deps, proto.ArchiveSessionEndRequest{OrgID: sessionExpiryOrg, Fingerprint: strings.Repeat("0", 64)})
	if !end.Success || end.Data.(proto.ArchiveSessionEndResponseData).Ended {
		t.Fatal("end of another session reported ended")
	}
	if sessionSlotValue(f.store, config.OrgArchiveSessionPrivateKeyPrefix+sessionExpiryOrg) != before {
		t.Fatal("end of another session deleted this one")
	}
}

func TestArchiveSessionEndWithItsFingerprintIsIdempotent(t *testing.T) {
	f := newAuditFixture(t)
	data := beginForExpiry(t, f)
	writeSessionSlotExpiry(t, f.store, f.clock.now().Unix())

	for i, want := range []bool{true, false} {
		end := HandleArchiveSessionEnd(f.deps, proto.ArchiveSessionEndRequest{OrgID: sessionExpiryOrg, Fingerprint: data.Fingerprint})
		if !end.Success || end.Data.(proto.ArchiveSessionEndResponseData).Ended != want {
			t.Fatalf("end #%d: success=%v data=%+v", i, end.Success, end.Data)
		}
		requireSessionSlotDeleted(t, f.store)
	}
}

// A slot whose expiry Keeper cannot trust is not deleted by an expiry rule
// or by an end, even an explicit one, and a begin does not replace it; only
// the confirmed discard removes it. (The device-wide slot of Keepers before lv90 is never touched
// by end at all: TestArchiveSession_EndLeavesTheDeviceWideSlot.)
func TestArchiveSessionEndKeepsASlotWithoutExpiry(t *testing.T) {
	f := newAuditFixture(t)
	data := beginForExpiry(t, f)
	legacy := writeSessionSlotWithoutExpiry(t, f.store)

	for _, req := range []proto.ArchiveSessionEndRequest{{OrgID: sessionExpiryOrg, Fingerprint: data.Fingerprint}} {
		end := HandleArchiveSessionEnd(f.deps, req)
		if !end.Success {
			t.Fatalf("end failed: %s", end.ErrorCode)
		}
		out := end.Data.(proto.ArchiveSessionEndResponseData)
		if out.Ended || !out.SlotWithoutExpiryKept {
			t.Fatalf("end of a slot without expiry reported %+v", out)
		}
		if sessionSlotValue(f.store, config.OrgArchiveSessionPrivateKeyPrefix+sessionExpiryOrg) != legacy {
			t.Fatal("end deleted a slot without expiry")
		}
	}
}

func TestArchiveSessionStartupSweepDestroysOnlyExpiredSlotsWithExpiry(t *testing.T) {
	f := newAuditFixture(t)
	beginForExpiry(t, f)

	SweepExpiredArchiveSession(f.deps)
	if sessionSlotValue(f.store, config.OrgArchiveSessionPrivateKeyPrefix+sessionExpiryOrg) == "" {
		t.Fatal("sweep deleted a live session")
	}

	record := sessionSlotValue(f.store, config.OrgArchiveSessionPrivateKeyPrefix+sessionExpiryOrg)
	legacy := writeSessionSlotWithoutExpiry(t, f.store)
	f.clock.unix += int64(24 * time.Hour / time.Second)
	SweepExpiredArchiveSession(f.deps)
	if sessionSlotValue(f.store, config.OrgArchiveSessionPrivateKeyPrefix+sessionExpiryOrg) != legacy {
		t.Fatal("sweep deleted a slot without expiry")
	}

	// The begin's own record, whose expiry passed during the 24 hours.
	if err := f.store.Set(config.Service, config.OrgArchiveSessionPrivateKeyPrefix+sessionExpiryOrg, record); err != nil {
		t.Fatal(err)
	}
	SweepExpiredArchiveSession(f.deps)
	requireSessionSlotDeleted(t, f.store)
}
