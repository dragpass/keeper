package handlers

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dragpass/keeper/config"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// The session slot record as this Keeper writes it: one header line carrying
// the expiry, then the private key PEM. Tests write it literally so they also
// pin the on-disk format.
const sessionSlotHeaderForTest = "dragpass-archive-session-v1 expires_at="

func sessionSlotPEM(t *testing.T, store keychain.SecretStore) string {
	t.Helper()
	value, err := store.Get(config.Service, config.OrgArchiveSessionPrivateKey)
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
	if err := store.Set(config.Service, config.OrgArchiveSessionPrivateKey, pem); err != nil {
		t.Fatal(err)
	}
	return pem
}

func writeSessionSlotExpiry(t *testing.T, store keychain.SecretStore, expiresAt int64) string {
	t.Helper()
	value := sessionSlotHeaderForTest + strconv.FormatInt(expiresAt, 10) + "\n" + sessionSlotPEM(t, store)
	if err := store.Set(config.Service, config.OrgArchiveSessionPrivateKey, value); err != nil {
		t.Fatal(err)
	}
	return value
}

func sessionSlotValue(store keychain.SecretStore, account string) string {
	value, _ := store.Get(config.Service, account)
	return value
}

func requireSessionSlotDeleted(t *testing.T, store keychain.SecretStore) {
	t.Helper()
	if sessionSlotValue(store, config.OrgArchiveSessionPrivateKey) != "" || sessionSlotValue(store, config.OrgArchiveSessionPublicKey) != "" {
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
	if sessionSlotValue(f.store, config.OrgArchiveSessionPrivateKey) != legacy {
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
	if sessionSlotValue(f.store, config.OrgArchiveSessionPrivateKey) != value {
		t.Fatal("slot beyond the upper bound was changed")
	}
}

// The decision in the fixture lives ten seconds, so the session's own upper
// bound is exercised below the decision check.
func TestArchiveSessionBeginBoundsTheSlotLifetime(t *testing.T) {
	f, req := authorizedCombineFixture(t)
	begun := f.clock.now()

	f.clock.unix = begun.Add(archiveSessionMaxTTL - time.Second).Unix()
	if live := archiveQuorumCombineAndRewrap(f.deps, req); !live.Success {
		t.Fatalf("session refused before its upper bound: %s", live.ErrorCode)
	}

	f.clock.unix = begun.Add(archiveSessionMaxTTL).Unix()
	expired := archiveQuorumCombineAndRewrap(f.deps, req)
	if expired.Success || expired.ErrorCode != "archive_session_expired" {
		t.Fatalf("session used at its upper bound: success=%v code=%s", expired.Success, expired.ErrorCode)
	}
	requireSessionSlotDeleted(t, f.store)
}

func TestArchiveSessionUpperBoundIsAboveTheServerSessionLifetime(t *testing.T) {
	// ariadne archiveQuorumSessionTTL is 30 minutes and starts after begin.
	if archiveSessionMaxTTL <= 30*time.Minute || archiveSessionMaxTTL > time.Hour {
		t.Fatalf("archiveSessionMaxTTL = %s", archiveSessionMaxTTL)
	}
}

func beginForExpiry(t *testing.T, f *auditFixture) proto.ArchiveSessionBeginResponseData {
	t.Helper()
	// The fixture already began one session; begin again so the test holds
	// the response.
	begun := HandleArchiveSessionBegin(f.deps, proto.ArchiveSessionBeginRequest{})
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
		Fingerprint: data.Fingerprint, ExpiresAt: now.Add(2 * time.Hour).UTC().Format(time.RFC3339),
	})
	if !later.Success {
		t.Fatalf("set expiry refused: %s", later.ErrorCode)
	}
	if got := later.Data.(proto.ArchiveSessionSetExpiryResponseData).ExpiresAt; got != data.ExpiresAt {
		t.Fatalf("a later server expiry extended the slot to %s", got)
	}

	sooner := now.Add(10 * time.Minute).UTC().Format(time.RFC3339)
	shortened := HandleArchiveSessionSetExpiry(f.deps, proto.ArchiveSessionSetExpiryRequest{Fingerprint: data.Fingerprint, ExpiresAt: sooner})
	if !shortened.Success || shortened.Data.(proto.ArchiveSessionSetExpiryResponseData).ExpiresAt != sooner {
		t.Fatalf("server expiry not applied: %+v", shortened)
	}

	f.clock.unix = now.Add(10 * time.Minute).Unix()
	again := HandleArchiveSessionSetExpiry(f.deps, proto.ArchiveSessionSetExpiryRequest{Fingerprint: data.Fingerprint, ExpiresAt: sooner})
	if again.Success || again.ErrorCode != "archive_session_expired" {
		t.Fatalf("slot used at the server expiry: success=%v code=%s", again.Success, again.ErrorCode)
	}
	requireSessionSlotDeleted(t, f.store)
}

func TestArchiveSessionSetExpiryRefusesAnotherSessionsFingerprint(t *testing.T) {
	f := newAuditFixture(t)
	beginForExpiry(t, f)
	before := sessionSlotValue(f.store, config.OrgArchiveSessionPrivateKey)

	response := HandleArchiveSessionSetExpiry(f.deps, proto.ArchiveSessionSetExpiryRequest{
		Fingerprint: strings.Repeat("0", 64), ExpiresAt: f.clock.now().Add(time.Minute).UTC().Format(time.RFC3339),
	})
	if response.Success || response.ErrorCode != "not_found" {
		t.Fatalf("expiry applied to another session: success=%v code=%s", response.Success, response.ErrorCode)
	}
	if sessionSlotValue(f.store, config.OrgArchiveSessionPrivateKey) != before {
		t.Fatal("refused set expiry changed the slot")
	}
}

func TestArchiveSessionSetExpiryInThePastDeletesTheSlot(t *testing.T) {
	f := newAuditFixture(t)
	data := beginForExpiry(t, f)

	response := HandleArchiveSessionSetExpiry(f.deps, proto.ArchiveSessionSetExpiryRequest{
		Fingerprint: data.Fingerprint, ExpiresAt: f.clock.now().UTC().Format(time.RFC3339),
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
		Fingerprint: data.Fingerprint, ExpiresAt: f.clock.now().Add(time.Minute).UTC().Format(time.RFC3339),
	})
	if response.Success || response.ErrorCode != "archive_session_expiry_unknown" {
		t.Fatalf("slot without expiry accepted an expiry: success=%v code=%s", response.Success, response.ErrorCode)
	}
	if sessionSlotValue(f.store, config.OrgArchiveSessionPrivateKey) != legacy {
		t.Fatal("slot without expiry changed")
	}
}

func TestArchiveSessionSetExpiryValidates(t *testing.T) {
	for name, req := range map[string]proto.ArchiveSessionSetExpiryRequest{
		"no fingerprint": {ExpiresAt: "2026-11-16T00:00:00Z"},
		"no expiry":      {Fingerprint: strings.Repeat("a", 64)},
		"bad expiry":     {Fingerprint: strings.Repeat("a", 64), ExpiresAt: "tomorrow"},
	} {
		if err := req.Validate(); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}

func TestArchiveSessionEndWithAnotherSessionsFingerprintKeepsTheSlot(t *testing.T) {
	f := newAuditFixture(t)
	beginForExpiry(t, f)
	before := sessionSlotValue(f.store, config.OrgArchiveSessionPrivateKey)

	end := HandleArchiveSessionEnd(f.deps, proto.ArchiveSessionEndRequest{Fingerprint: strings.Repeat("0", 64)})
	if !end.Success || end.Data.(proto.ArchiveSessionEndResponseData).Ended {
		t.Fatal("end of another session reported ended")
	}
	if sessionSlotValue(f.store, config.OrgArchiveSessionPrivateKey) != before {
		t.Fatal("end of another session deleted this one")
	}
}

func TestArchiveSessionEndWithItsFingerprintIsIdempotent(t *testing.T) {
	f := newAuditFixture(t)
	data := beginForExpiry(t, f)
	writeSessionSlotExpiry(t, f.store, f.clock.now().Unix()-1)

	for i, want := range []bool{true, false} {
		end := HandleArchiveSessionEnd(f.deps, proto.ArchiveSessionEndRequest{Fingerprint: data.Fingerprint})
		if !end.Success || end.Data.(proto.ArchiveSessionEndResponseData).Ended != want {
			t.Fatalf("end #%d: success=%v data=%+v", i, end.Success, end.Data)
		}
		requireSessionSlotDeleted(t, f.store)
	}
}

// lv90 (keeper #206) forbids deleting a slot written before lv100 F1 without
// the user's confirmed discard, so even an explicit end leaves it in place.
func TestArchiveSessionEndKeepsASlotWithoutExpiry(t *testing.T) {
	f := newAuditFixture(t)
	data := beginForExpiry(t, f)
	legacy := writeSessionSlotWithoutExpiry(t, f.store)

	for _, req := range []proto.ArchiveSessionEndRequest{{}, {Fingerprint: data.Fingerprint}} {
		end := HandleArchiveSessionEnd(f.deps, req)
		if !end.Success {
			t.Fatalf("end failed: %s", end.ErrorCode)
		}
		out := end.Data.(proto.ArchiveSessionEndResponseData)
		if out.Ended || !out.SlotWithoutExpiryKept {
			t.Fatalf("end of a slot without expiry reported %+v", out)
		}
		if sessionSlotValue(f.store, config.OrgArchiveSessionPrivateKey) != legacy {
			t.Fatal("end deleted a slot without expiry")
		}
	}
}

func TestArchiveSessionStartupSweepDestroysOnlyExpiredSlotsWithExpiry(t *testing.T) {
	f := newAuditFixture(t)
	beginForExpiry(t, f)

	SweepExpiredArchiveSession(f.deps)
	if sessionSlotValue(f.store, config.OrgArchiveSessionPrivateKey) == "" {
		t.Fatal("sweep deleted a live session")
	}

	legacy := writeSessionSlotWithoutExpiry(t, f.store)
	f.clock.unix += int64(24 * time.Hour / time.Second)
	SweepExpiredArchiveSession(f.deps)
	if sessionSlotValue(f.store, config.OrgArchiveSessionPrivateKey) != legacy {
		t.Fatal("sweep deleted a slot without expiry")
	}

	writeSessionSlotExpiry(t, f.store, f.clock.now().Unix())
	SweepExpiredArchiveSession(f.deps)
	requireSessionSlotDeleted(t, f.store)
}
