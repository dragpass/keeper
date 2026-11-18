// archive_session_sweeper_test.go — the periodic sweep (lv100 F1, D1).

package handlers

import (
	"context"
	"testing"
	"time"

	"github.com/dragpass/keeper/config"
)

// Each tick sweeps: a trusted slot whose expiry passed is deleted with its
// index entry; a live slot, an untrusted slot and the device-wide slot stay.
// Ticks are sent by the test, so nothing waits on real time; a tick send
// returns only once the sweeper took it, so the send after a tick shows
// that tick's sweep finished.
func TestArchiveSessionSweeper_DeletesOnlyTrustedExpiredSlotsOnEachTick(t *testing.T) {
	deps, store, clock := newOrgSessionDeps(t)
	a := beginOrgSession(t, deps, testOrgA)
	beginOrgSession(t, deps, testOrgB)
	beginOrgSession(t, deps, testOrgC)
	writeOrgSlot(t, store, testOrgC, orgSlotPEM(t, store, testOrgC)) // untrusted: no header
	cValue := orgSlotValue(store, testOrgC)
	legacyPublic := saveLegacyDeviceSession(t, store)

	ticks := make(chan time.Time)
	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		RunArchiveSessionSweeper(ctx, deps, ticks)
	}()
	tick := func() {
		select {
		case ticks <- time.Time{}:
		case <-time.After(10 * time.Second):
			t.Fatal("the sweeper did not take a tick")
		}
	}

	tick()
	tick()
	if !archiveSessionFingerprintMatches(deps, testOrgA, a.Fingerprint) {
		t.Fatal("a live slot was swept")
	}

	writeOrgSlotExpiry(t, store, testOrgA, clock.Now())
	clock.Set(clock.Now().Add(24 * time.Hour)) // B expires too
	tick()
	tick()
	requireOrgSlotGone(t, store, testOrgA)
	requireOrgSlotGone(t, store, testOrgB)
	if orgSlotValue(store, testOrgC) != cValue {
		t.Fatal("the sweep changed an untrusted slot")
	}
	if got := sessionIndexOrgs(t, store); len(got) != 1 || got[0] != testOrgC {
		t.Fatalf("index after the sweep: %v", got)
	}
	if got, _ := store.Get(config.Service, config.LegacyOrgArchiveSessionPublicKey); got != legacyPublic {
		t.Fatal("the sweep changed the device-wide slot")
	}

	cancel()
	select {
	case <-stopped:
	case <-time.After(10 * time.Second):
		t.Fatal("the sweeper did not stop with its context")
	}
}
