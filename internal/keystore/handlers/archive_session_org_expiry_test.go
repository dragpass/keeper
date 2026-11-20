// archive_session_org_expiry_test.go — the lv100 F1 session-key expiry on
// the per-organization slot of lv90 K0.
//
// Each organization's slot carries its own expiry. Every action names the
// organization it acts on and never reads, shortens, ends or deletes another
// organization's slot; the startup sweep judges each slot on its own expiry;
// the device-wide slot of a Keeper before lv90 is preserved even after confirmed discard.

package handlers

import (
	"encoding/json"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dragpass/keeper/config"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/testdouble"
)

const testOrgC = "cccccccc-cccc-4ccc-8ccc-cccccccccccd"

// orgSessionClock is a settable clock shared by the deps of one test.
type orgSessionClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *orgSessionClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *orgSessionClock) Set(t time.Time) {
	c.mu.Lock()
	c.now = t
	c.mu.Unlock()
}

func newOrgSessionDeps(t *testing.T) (Deps, *testdouble.MemorySecretStore, *orgSessionClock) {
	t.Helper()
	deps, _, store := newTestDeps(t)
	setSlotTestOwner(t, deps, slotTestAccount)
	clock := &orgSessionClock{now: time.Unix(1789000000, 0)}
	deps.Clock = clock.Now
	return deps, store, clock
}

func beginOrgSession(t *testing.T, deps Deps, orgID string) proto.ArchiveSessionBeginResponseData {
	t.Helper()
	resp := HandleArchiveSessionBegin(deps, proto.ArchiveSessionBeginRequest{OrgID: orgID})
	if !resp.Success {
		t.Fatalf("begin %s: %+v", orgID, resp)
	}
	return resp.Data.(proto.ArchiveSessionBeginResponseData)
}

func orgSlotValue(store keychain.SecretStore, orgID string) string {
	value, _ := store.Get(config.Service, config.OrgArchiveSessionPrivateKeyPrefix+orgID)
	return value
}

func orgSlotPublic(store keychain.SecretStore, orgID string) string {
	value, _ := store.Get(config.Service, config.OrgArchiveSessionPublicKeyPrefix+orgID)
	return value
}

func orgSlotPEM(t *testing.T, store keychain.SecretStore, orgID string) string {
	t.Helper()
	value := orgSlotValue(store, orgID)
	start := strings.Index(value, "-----BEGIN")
	if start < 0 {
		t.Fatalf("no PEM in %s's slot", orgID)
	}
	return value[start:]
}

func writeOrgSlot(t *testing.T, store keychain.SecretStore, orgID, value string) {
	t.Helper()
	if err := store.Set(config.Service, config.OrgArchiveSessionPrivateKeyPrefix+orgID, value); err != nil {
		t.Fatal(err)
	}
}

func writeOrgSlotExpiry(t *testing.T, store keychain.SecretStore, orgID string, expiresAt time.Time) string {
	t.Helper()
	return rewriteSessionSlotExpiry(t, store, config.OrgArchiveSessionPrivateKeyPrefix+orgID, expiresAt)
}

func sessionIndexOrgs(t *testing.T, store keychain.SecretStore) []string {
	t.Helper()
	orgs, err := keychain.ListArchiveSessionOrgs(store)
	if err != nil {
		t.Fatal(err)
	}
	sorted := slices.Clone(orgs)
	slices.Sort(sorted)
	return sorted
}

func requireOrgSlotGone(t *testing.T, store keychain.SecretStore, orgID string) {
	t.Helper()
	if orgSlotValue(store, orgID) != "" || orgSlotPublic(store, orgID) != "" {
		t.Fatalf("%s's session slot was not deleted", orgID)
	}
}

func setExpiry(deps Deps, orgID, fingerprint string, at time.Time) proto.BaseResponse {
	return HandleArchiveSessionSetExpiry(deps, proto.ArchiveSessionSetExpiryRequest{
		OrgID: orgID, Fingerprint: fingerprint, ExpiresAt: at.UTC().Format(time.RFC3339),
	})
}

// --- (a) cross-organization isolation ---------------------------------------

// A fingerprint is checked against the named organization's slot only: org
// A's set_expiry and end carrying org B's fingerprint find no session and
// change nothing, in either slot.
func TestArchiveSessionOrgSlot_AnotherOrgsFingerprintChangesNothing(t *testing.T) {
	deps, store, clock := newOrgSessionDeps(t)
	beginOrgSession(t, deps, testOrgA)
	b := beginOrgSession(t, deps, testOrgB)
	before := store.Snapshot()

	set := setExpiry(deps, testOrgA, b.Fingerprint, clock.Now().Add(time.Minute))
	if set.Success || set.ErrorCode != string(errs.ErrCodeNotFound) {
		t.Fatalf("set_expiry for A with B's fingerprint: %+v", set)
	}
	end := HandleArchiveSessionEnd(deps, proto.ArchiveSessionEndRequest{OrgID: testOrgA, Fingerprint: b.Fingerprint})
	if !end.Success || end.Data.(proto.ArchiveSessionEndResponseData).Ended {
		t.Fatalf("end for A with B's fingerprint: %+v", end)
	}
	if !reflect.DeepEqual(before, store.Snapshot()) {
		t.Fatal("a request for A carrying B's fingerprint changed the keychain")
	}
}

// Shortening, ending and the expiry delete act on the named organization's
// slot and index entry alone.
func TestArchiveSessionOrgSlot_SetExpiryEndAndExpiryDeleteActOnTheirOrgOnly(t *testing.T) {
	deps, store, clock := newOrgSessionDeps(t)
	a := beginOrgSession(t, deps, testOrgA)
	beginOrgSession(t, deps, testOrgB)
	bValue, bPublic := orgSlotValue(store, testOrgB), orgSlotPublic(store, testOrgB)
	requireB := func(step string) {
		t.Helper()
		if orgSlotValue(store, testOrgB) != bValue || orgSlotPublic(store, testOrgB) != bPublic {
			t.Fatalf("%s for A changed B's slot", step)
		}
		if !slices.Contains(sessionIndexOrgs(t, store), testOrgB) {
			t.Fatalf("%s for A dropped B's index entry", step)
		}
	}

	if resp := setExpiry(deps, testOrgA, a.Fingerprint, clock.Now().Add(time.Minute)); !resp.Success {
		t.Fatalf("set_expiry A: %+v", resp)
	}
	requireB("set_expiry")

	clock.Set(clock.Now().Add(time.Minute))
	if resp := setExpiry(deps, testOrgA, a.Fingerprint, clock.Now().Add(time.Minute)); resp.ErrorCode != string(errs.ErrCodeArchiveSessionExpired) {
		t.Fatalf("set_expiry A after its expiry: %+v", resp)
	}
	requireOrgSlotGone(t, store, testOrgA)
	requireB("the expiry delete")

	a = beginOrgSession(t, deps, testOrgA)
	if resp := HandleArchiveSessionEnd(deps, proto.ArchiveSessionEndRequest{OrgID: testOrgA, Fingerprint: a.Fingerprint}); !resp.Success || !resp.Data.(proto.ArchiveSessionEndResponseData).Ended {
		t.Fatalf("end A: %+v", resp)
	}
	requireOrgSlotGone(t, store, testOrgA)
	requireB("end")
	if got := sessionIndexOrgs(t, store); !reflect.DeepEqual(got, []string{testOrgB}) {
		t.Fatalf("index after A ended: %v", got)
	}
}

// An expired slot of org A is refused and deleted by A's combine; org B's
// live slot stays and still combines.
func TestArchiveSessionOrgSlot_ExpiredCombineDeletesOnlyItsOrg(t *testing.T) {
	deps, store, clock := newOrgSessionDeps(t)
	a := beginOrgSession(t, deps, testOrgA)
	b := beginOrgSession(t, deps, testOrgB)
	writeOrgSlotExpiry(t, store, testOrgA, clock.Now())
	bValue := orgSlotValue(store, testOrgB)

	reqA, _ := sessionCombineRequest(t, testOrgA, a.SessionPublicKey, sessionTestDEK())
	if resp := archiveQuorumCombineAndRewrap(deps, testOrgA, reqA); resp.Success || resp.ErrorCode != string(errs.ErrCodeArchiveSessionExpired) {
		t.Fatalf("combine with A's expired slot: %+v", resp)
	}
	requireOrgSlotGone(t, store, testOrgA)
	if orgSlotValue(store, testOrgB) != bValue {
		t.Fatal("A's expired combine changed B's slot")
	}
	reqB, member := sessionCombineRequest(t, testOrgB, b.SessionPublicKey, sessionTestDEK())
	respB := archiveQuorumCombineAndRewrap(deps, testOrgB, reqB)
	assertMemberGrantOpens(t, respB, member, sessionGrantContext(testOrgB), sessionTestDEK())
}

// A combine for org A never falls back to org B's slot, even when the
// shares were wrapped to B's session key.
func TestArchiveSessionOrgSlot_CombineNeverUsesAnotherOrgsKey(t *testing.T) {
	deps, store, _ := newOrgSessionDeps(t)
	b := beginOrgSession(t, deps, testOrgB)
	bValue := orgSlotValue(store, testOrgB)
	req, _ := sessionCombineRequest(t, testOrgA, b.SessionPublicKey, sessionTestDEK())

	if resp := archiveQuorumCombineAndRewrap(deps, testOrgA, req); resp.Success || resp.ErrorCode != string(errs.ErrCodeNotFound) {
		t.Fatalf("combine for A with no A session: %+v", resp)
	}
	beginOrgSession(t, deps, testOrgA)
	if resp := archiveQuorumCombineAndRewrap(deps, testOrgA, req); resp.Success {
		t.Fatal("combine for A opened shares wrapped to B's session key")
	}
	if orgSlotValue(store, testOrgB) != bValue {
		t.Fatal("A's combine changed B's slot")
	}
}

// The startup sweep judges every indexed organization on its own expiry: an
// expired slot goes, a live one and one without a trusted expiry stay.
func TestArchiveSessionOrgSlot_SweepJudgesEachOrgOnItsOwnExpiry(t *testing.T) {
	deps, store, clock := newOrgSessionDeps(t)
	beginOrgSession(t, deps, testOrgA)
	beginOrgSession(t, deps, testOrgB)
	beginOrgSession(t, deps, testOrgC)
	writeOrgSlotExpiry(t, store, testOrgA, clock.Now())
	writeOrgSlotExpiry(t, store, testOrgB, clock.Now().Add(time.Second))
	cValue := orgSlotPEM(t, store, testOrgC)
	writeOrgSlot(t, store, testOrgC, cValue)
	bValue := orgSlotValue(store, testOrgB)

	SweepExpiredArchiveSession(deps)
	requireOrgSlotGone(t, store, testOrgA)
	if orgSlotValue(store, testOrgB) != bValue || orgSlotValue(store, testOrgC) != cValue {
		t.Fatal("the sweep changed a live slot or one without a trusted expiry")
	}
	if got := sessionIndexOrgs(t, store); !reflect.DeepEqual(got, []string{testOrgB, testOrgC}) {
		t.Fatalf("index after the sweep: %v", got)
	}
}

// An index entry whose slot is gone (a crash between the index write and the
// slot write) is dropped by the sweep.
func TestArchiveSessionOrgSlot_SweepDropsAnEntryWithoutASlot(t *testing.T) {
	deps, store, _ := newOrgSessionDeps(t)
	beginOrgSession(t, deps, testOrgB)
	if err := keychain.AddArchiveSessionOrg(store, testOrgA); err != nil {
		t.Fatal(err)
	}
	SweepExpiredArchiveSession(deps)
	if got := sessionIndexOrgs(t, store); !reflect.DeepEqual(got, []string{testOrgB}) {
		t.Fatalf("index after the sweep: %v", got)
	}
}

// Begin records its organization in the index before the slot, and a
// refused begin records nothing.
func TestArchiveSessionOrgSlot_BeginIndexesItsOrg(t *testing.T) {
	deps, store, _ := newOrgSessionDeps(t)
	beginOrgSession(t, deps, testOrgA)
	if resp := HandleArchiveSessionBegin(deps, proto.ArchiveSessionBeginRequest{OrgID: testOrgA}); resp.ErrorCode != string(errs.ErrCodeArchiveSessionActive) {
		t.Fatalf("second begin of A: success=%v code=%q", resp.Success, resp.ErrorCode)
	}
	beginOrgSession(t, deps, testOrgB)
	if got := sessionIndexOrgs(t, store); !reflect.DeepEqual(got, []string{testOrgA, testOrgB}) {
		t.Fatalf("index: %v", got)
	}
	raw, _ := store.Get(config.Service, config.OrgArchiveSessionIndex)
	var record map[string]any
	if err := json.Unmarshal([]byte(raw), &record); err != nil || record["v"] != float64(1) || strings.Contains(raw, "BEGIN") {
		t.Fatalf("index record holds more than organization ids: %q", raw)
	}
}

// An index Keeper cannot read does not stop a session: begin replaces it,
// and every use still refuses an expired slot on its own clock.
func TestArchiveSessionOrgSlot_UnreadableIndexDoesNotBlockBeginOrUseRefusal(t *testing.T) {
	deps, store, clock := newOrgSessionDeps(t)
	a := beginOrgSession(t, deps, testOrgA)
	if err := store.Set(config.Service, config.OrgArchiveSessionIndex, "{not json"); err != nil {
		t.Fatal(err)
	}
	SweepExpiredArchiveSession(deps) // skipped, nothing changed
	if orgSlotValue(store, testOrgA) == "" {
		t.Fatal("the sweep acted on an unreadable index")
	}
	clock.Set(clock.Now().Add(archiveSessionMaxTTL))
	if resp := setExpiry(deps, testOrgA, a.Fingerprint, clock.Now().Add(time.Minute)); resp.ErrorCode != string(errs.ErrCodeArchiveSessionExpired) {
		t.Fatalf("use of an expired slot with an unreadable index: %+v", resp)
	}
	beginOrgSession(t, deps, testOrgB)
	if got := sessionIndexOrgs(t, store); !reflect.DeepEqual(got, []string{testOrgB}) {
		t.Fatalf("index after begin replaced an unreadable one: %v", got)
	}
}

// --- (b) refusal at every use ------------------------------------------------

// A per-organization record whose expiry Keeper cannot trust is refused by
// every reader with archive_session_expiry_unknown and is not deleted by a
// use or the sweep.
func TestArchiveSessionOrgSlot_UntrustedRecordsAreRefusedAndKept(t *testing.T) {
	deps, store, clock := newOrgSessionDeps(t)
	a := beginOrgSession(t, deps, testOrgA)
	pem := orgSlotPEM(t, store, testOrgA)
	now := clock.Now()
	records := map[string]string{
		"no header":              pem,
		"header without newline": sessionSlotHeaderForTest + strconv.FormatInt(now.Add(time.Minute).Unix(), 10),
		"header without key":     sessionSlotHeaderForTest + strconv.FormatInt(now.Add(time.Minute).Unix(), 10) + "\n",
		"non-numeric expiry":     sessionSlotHeaderForTest + "soon\n" + pem,
		"zero expiry":            sessionSlotHeaderForTest + "0\n" + pem,
		"negative expiry":        sessionSlotHeaderForTest + "-5\n" + pem,
		"other version":          "dragpass-archive-session-v2 expires_at=" + strconv.FormatInt(now.Add(time.Minute).Unix(), 10) + "\n" + pem,
		"beyond the upper bound": sessionSlotHeaderForTest + strconv.FormatInt(now.Add(archiveSessionMaxTTL).Unix()+1, 10) + "\n" + pem,
	}
	req, _ := sessionCombineRequest(t, testOrgA, a.SessionPublicKey, sessionTestDEK())
	for name, record := range records {
		t.Run(name, func(t *testing.T) {
			writeOrgSlot(t, store, testOrgA, record)
			uses := map[string]proto.BaseResponse{
				"combine":    archiveQuorumCombineAndRewrap(deps, testOrgA, req),
				"set_expiry": setExpiry(deps, testOrgA, a.Fingerprint, now.Add(time.Minute)),
			}
			want := "archive_session_owner_unknown"
			for use, resp := range uses {
				if resp.Success || resp.Data != nil || resp.ErrorCode != want {
					t.Fatalf("%s with an untrusted record: %+v", use, resp)
				}
			}
			SweepExpiredArchiveSession(deps)
			if name != "beyond the upper bound" {
				// Without a parsable expiry no clock makes it expired. A
				// record beyond the bound is judged by the plain expiry
				// rule once that time has really passed.
				clock.Set(now.Add(24 * time.Hour))
				SweepExpiredArchiveSession(deps)
				clock.Set(now)
			}
			if orgSlotValue(store, testOrgA) != record {
				t.Fatal("an untrusted record was changed or deleted by a use or the sweep")
			}
		})
	}
}

// Only the combine and the session actions read a session slot. The archive
// re-grant, the share re-wrap and the other archive paths never do, so no
// expiry check can be skipped through them.
func TestArchiveSessionOrgSlot_NoOtherArchivePathReadsASessionSlot(t *testing.T) {
	f := newArchiveSelfFixture(t)
	probe := &sessionAccountProbe{SecretStore: f.store}
	f.deps.Store = probe
	_ = f.regrant(f.own.PublicKey)
	_ = HandleArchiveShareRewrap(f.deps, proto.ArchiveShareRewrapRequest{})
	_ = HandleArchiveKeyStatus(f.deps, proto.ArchiveKeyStatusRequest{})
	if probe.touched.Load() != 0 {
		t.Fatalf("%d session slot accesses outside the session actions", probe.touched.Load())
	}
}

// sessionAccountProbe counts accesses to any session account: the
// per-organization slots, the index and the device-wide slot.
type sessionAccountProbe struct {
	keychain.SecretStore
	touched atomic.Int32
}

func isSessionAccount(account string) bool {
	return strings.HasPrefix(account, config.LegacyOrgArchiveSessionPrivateKey) ||
		strings.HasPrefix(account, config.LegacyOrgArchiveSessionPublicKey) ||
		account == config.OrgArchiveSessionIndex
}

func (p *sessionAccountProbe) Get(service, account string) (string, error) {
	if isSessionAccount(account) {
		p.touched.Add(1)
	}
	return p.SecretStore.Get(service, account)
}

func (p *sessionAccountProbe) Set(service, account, value string) error {
	if isSessionAccount(account) {
		p.touched.Add(1)
	}
	return p.SecretStore.Set(service, account, value)
}

func (p *sessionAccountProbe) Delete(service, account string) error {
	if isSessionAccount(account) {
		p.touched.Add(1)
	}
	return p.SecretStore.Delete(service, account)
}

// --- (c) the process lock and concurrent actors ------------------------------

// lockedSessionStore records session-account accesses made without the
// session process lock.
type lockedSessionStore struct {
	keychain.SecretStore
	locked   *atomic.Bool
	unlocked atomic.Int32
}

func (s *lockedSessionStore) note(account string) {
	if isSessionAccount(account) && !s.locked.Load() {
		s.unlocked.Add(1)
	}
}

func (s *lockedSessionStore) Get(service, account string) (string, error) {
	s.note(account)
	return s.SecretStore.Get(service, account)
}

func (s *lockedSessionStore) Set(service, account, value string) error {
	s.note(account)
	return s.SecretStore.Set(service, account, value)
}

func (s *lockedSessionStore) Delete(service, account string) error {
	s.note(account)
	return s.SecretStore.Delete(service, account)
}

// Every read, write and delete of a session slot, the index or the
// device-wide slot runs under the keychain process lock, so a Keeper process
// that starts (sweep) while the App service begins, ends or discards never
// acts on a read taken before another process's write.
func TestArchiveSessionOrgSlot_EverySessionAccessHoldsTheProcessLock(t *testing.T) {
	deps, mem, clock := newOrgSessionDeps(t)
	var locked atomic.Bool
	store := &lockedSessionStore{SecretStore: mem, locked: &locked}
	deps.Store = store
	restore := archiveSessionProcessLock
	t.Cleanup(func() { archiveSessionProcessLock = restore })
	archiveSessionProcessLock = func(s keychain.SecretStore, fn func() error) error {
		return restore(s, func() error {
			locked.Store(true)
			defer locked.Store(false)
			return fn()
		})
	}

	a := beginOrgSession(t, deps, testOrgA)
	b := beginOrgSession(t, deps, testOrgB)
	req, _ := sessionCombineRequest(t, testOrgA, a.SessionPublicKey, sessionTestDEK())
	actions := []func(){
		func() { archiveQuorumCombineAndRewrap(deps, testOrgA, req) },
		func() { setExpiry(deps, testOrgB, b.Fingerprint, clock.Now().Add(time.Minute)) },
		func() {
			HandleArchiveSessionEnd(deps, proto.ArchiveSessionEndRequest{OrgID: testOrgB, Fingerprint: b.Fingerprint})
		},
		func() { SweepExpiredArchiveSession(deps) },
		func() {
			HandleArchiveSessionStatus(deps, proto.ArchiveSessionStatusRequest{OrgID: testOrgA, Fingerprint: a.Fingerprint})
		},
		func() {
			HandleArchiveSessionDiscard(deps, proto.ArchiveSessionDiscardRequest{OrgID: testOrgA, Fingerprint: a.Fingerprint, ConfirmDiscard: true})
		},
		func() { saveLegacyDeviceSession(t, mem) },
		func() { HandleArchiveSessionBegin(deps, proto.ArchiveSessionBeginRequest{OrgID: testOrgC}) },
		func() {
			HandleArchiveSessionLegacyDiscard(deps, proto.ArchiveSessionLegacyDiscardRequest{ConfirmDiscard: true})
		},
	}
	for _, action := range actions {
		action()
	}
	if n := store.unlocked.Load(); n != 0 {
		t.Fatalf("%d session account accesses ran outside the process lock", n)
	}
}

// raceActors arms each actor, releases them together through one barrier
// and waits for all of them. The wait has a bound only to report a deadlock.
func raceActors(t *testing.T, actors ...func()) {
	t.Helper()
	var armed, done sync.WaitGroup
	release := make(chan struct{})
	for _, actor := range actors {
		armed.Add(1)
		done.Add(1)
		go func() {
			defer done.Done()
			armed.Done()
			<-release
			actor()
		}()
	}
	armed.Wait()
	close(release)
	finished := make(chan struct{})
	go func() { done.Wait(); close(finished) }()
	select {
	case <-finished:
	case <-time.After(30 * time.Second):
		t.Fatal("concurrent session actors deadlocked")
	}
}

const sessionRaceRounds = 8

// A startup sweep and a begin of the same organization race while the old
// slot is expired: the new session always survives, whichever runs first.
func TestArchiveSessionOrgSlot_SweepNeverDeletesASessionBegunConcurrently(t *testing.T) {
	for round := range sessionRaceRounds {
		deps, store, clock := newOrgSessionDeps(t)
		beginOrgSession(t, deps, testOrgA)
		writeOrgSlotExpiry(t, store, testOrgA, clock.Now())
		var fresh proto.BaseResponse
		raceActors(t,
			func() { SweepExpiredArchiveSession(deps) },
			func() { fresh = HandleArchiveSessionBegin(deps, proto.ArchiveSessionBeginRequest{OrgID: testOrgA}) },
		)
		if !fresh.Success {
			t.Fatalf("round %d: begin: %+v", round, fresh)
		}
		fp := fresh.Data.(proto.ArchiveSessionBeginResponseData).Fingerprint
		if !archiveSessionFingerprintMatches(deps, testOrgA, fp) || orgSlotValue(store, testOrgA) == "" {
			t.Fatalf("round %d: the sweep deleted a session begun concurrently", round)
		}
		if !slices.Contains(sessionIndexOrgs(t, store), testOrgA) {
			t.Fatalf("round %d: the sweep dropped the index entry of a session begun concurrently", round)
		}
	}
}

// A late end of the earlier session (its fingerprint) races a new begin of
// the same organization once the earlier one has expired (a begin over a
// live session is refused): the new session always survives.
func TestArchiveSessionOrgSlot_LateEndNeverDeletesANewSession(t *testing.T) {
	for round := range sessionRaceRounds {
		deps, store, clock := newOrgSessionDeps(t)
		old := beginOrgSession(t, deps, testOrgA)
		writeOrgSlotExpiry(t, store, testOrgA, clock.Now())
		var fresh proto.BaseResponse
		raceActors(t,
			func() {
				HandleArchiveSessionEnd(deps, proto.ArchiveSessionEndRequest{OrgID: testOrgA, Fingerprint: old.Fingerprint})
			},
			func() { fresh = HandleArchiveSessionBegin(deps, proto.ArchiveSessionBeginRequest{OrgID: testOrgA}) },
		)
		if !fresh.Success {
			t.Fatalf("round %d: begin after the old session expired: %q", round, fresh.ErrorCode)
		}
		fp := fresh.Data.(proto.ArchiveSessionBeginResponseData).Fingerprint
		if !archiveSessionFingerprintMatches(deps, testOrgA, fp) || orgSlotValue(store, testOrgA) == "" {
			t.Fatalf("round %d: a late end deleted the new session", round)
		}
	}
}

// A combine at the slot's expiry races a new begin of the same organization:
// the combine never succeeds with the expired key, and the new session
// survives.
func TestArchiveSessionOrgSlot_ExpiredCombineRacingABeginNeverSucceeds(t *testing.T) {
	for round := range sessionRaceRounds {
		deps, store, clock := newOrgSessionDeps(t)
		old := beginOrgSession(t, deps, testOrgA)
		writeOrgSlotExpiry(t, store, testOrgA, clock.Now())
		req, _ := sessionCombineRequest(t, testOrgA, old.SessionPublicKey, sessionTestDEK())
		var combined, fresh proto.BaseResponse
		raceActors(t,
			func() { combined = archiveQuorumCombineAndRewrap(deps, testOrgA, req) },
			func() { fresh = HandleArchiveSessionBegin(deps, proto.ArchiveSessionBeginRequest{OrgID: testOrgA}) },
		)
		if combined.Success {
			t.Fatalf("round %d: a combine succeeded with an expired session key", round)
		}
		fp := fresh.Data.(proto.ArchiveSessionBeginResponseData).Fingerprint
		if !archiveSessionFingerprintMatches(deps, testOrgA, fp) {
			t.Fatalf("round %d: the expired combine deleted the new session", round)
		}
	}
}

// Begins of different organizations racing each other and a sweep keep
// every index entry: the index read-modify-write is serialized.
func TestArchiveSessionOrgSlot_ConcurrentBeginsKeepEveryIndexEntry(t *testing.T) {
	for round := range sessionRaceRounds {
		deps, store, _ := newOrgSessionDeps(t)
		raceActors(t,
			func() { beginOrgSession(t, deps, testOrgA) },
			func() { beginOrgSession(t, deps, testOrgB) },
			func() { beginOrgSession(t, deps, testOrgC) },
			func() { SweepExpiredArchiveSession(deps) },
		)
		if got := sessionIndexOrgs(t, store); !reflect.DeepEqual(got, []string{testOrgA, testOrgB, testOrgC}) {
			t.Fatalf("round %d: index after concurrent begins: %v", round, got)
		}
	}
}

// --- (d) the device-wide slot of a Keeper before lv90 ------------------------

// The device-wide slot is refused for use and never deleted or changed
// automatically, whatever it holds: a bare key from a released Keeper, or a
// record with an expiry (long passed) from a development build of lv100 F1
// that wrote the device-wide name. Begin, end, set_expiry, combine and the
// startup sweep all leave it byte for byte; even confirmed discard
// preserves it.
func TestArchiveSessionLegacySlot_PreservesBothFormatsAfterConfirmedDiscard(t *testing.T) {
	for _, form := range []string{"bare key", "expired record"} {
		t.Run(form, func(t *testing.T) {
			deps, store, clock := newOrgSessionDeps(t)
			a := beginOrgSession(t, deps, testOrgA)
			legacyPublic := saveLegacyDeviceSession(t, store)
			if form == "expired record" {
				priv, _ := store.Get(config.Service, config.LegacyOrgArchiveSessionPrivateKey)
				record := sessionSlotHeaderForTest + strconv.FormatInt(clock.Now().Add(-time.Hour).Unix(), 10) + "\n" + priv
				if err := store.Set(config.Service, config.LegacyOrgArchiveSessionPrivateKey, record); err != nil {
					t.Fatal(err)
				}
			}
			legacyPrivate, _ := store.Get(config.Service, config.LegacyOrgArchiveSessionPrivateKey)
			requireLegacy := func(step string) {
				t.Helper()
				gotPriv, _ := store.Get(config.Service, config.LegacyOrgArchiveSessionPrivateKey)
				gotPub, _ := store.Get(config.Service, config.LegacyOrgArchiveSessionPublicKey)
				if gotPriv != legacyPrivate || gotPub != legacyPublic {
					t.Fatalf("%s changed the device-wide slot", step)
				}
			}

			if resp := HandleArchiveSessionBegin(deps, proto.ArchiveSessionBeginRequest{OrgID: testOrgB}); resp.ErrorCode != string(errs.ErrCodeArchiveSessionLegacySlotPresent) {
				t.Fatalf("begin with the device-wide slot: %+v", resp)
			}
			requireLegacy("begin")
			req, _ := sessionCombineRequest(t, testOrgB, legacyPublic, sessionTestDEK())
			if resp := archiveQuorumCombineAndRewrap(deps, testOrgB, req); resp.Success || resp.ErrorCode != string(errs.ErrCodeNotFound) {
				t.Fatalf("combine for an org without a session, shares to the device-wide key: %+v", resp)
			}
			requireLegacy("combine")
			legacyFP := fingerprintBase64Public(legacyPublic)
			if resp := setExpiry(deps, testOrgB, legacyFP, clock.Now().Add(time.Minute)); resp.Success {
				t.Fatalf("set_expiry reached the device-wide slot: %+v", resp)
			}
			requireLegacy("set_expiry")
			for _, end := range []proto.ArchiveSessionEndRequest{{OrgID: testOrgB, Fingerprint: legacyFP}, {OrgID: testOrgA, Fingerprint: a.Fingerprint}} {
				if resp := HandleArchiveSessionEnd(deps, end); !resp.Success {
					t.Fatalf("end: %+v", resp)
				}
			}
			requireLegacy("end")
			clock.Set(clock.Now().Add(24 * time.Hour))
			SweepExpiredArchiveSession(deps)
			requireLegacy("the startup sweep")
			if slices.Contains(sessionIndexOrgs(t, store), "") {
				t.Fatal("the device-wide slot entered the index")
			}

			resp := HandleArchiveSessionLegacyDiscard(deps, proto.ArchiveSessionLegacyDiscardRequest{ConfirmDiscard: true})
			if resp.Success || resp.ErrorCode != string(errs.ErrCodeArchiveSessionLegacySlotPresent) {
				t.Fatalf("confirmed discard should refuse, code=%q", resp.ErrorCode)
			}
			requireLegacy("confirmed discard")
		})
	}
}

// The process start (prepareProcessApp → SweepExpiredArchiveSession) is
// covered above; the discard leaves organization slots and the index alone.
func TestArchiveSessionLegacySlot_DiscardLeavesOrgSlotsAndIndex(t *testing.T) {
	deps, store, _ := newOrgSessionDeps(t)
	beginOrgSession(t, deps, testOrgA)
	saveLegacyDeviceSession(t, store)
	aValue, index := orgSlotValue(store, testOrgA), sessionIndexOrgs(t, store)
	if resp := HandleArchiveSessionLegacyDiscard(deps, proto.ArchiveSessionLegacyDiscardRequest{ConfirmDiscard: true}); resp.Success || resp.ErrorCode != string(errs.ErrCodeArchiveSessionLegacySlotPresent) {
		t.Fatalf("discard: %+v", resp)
	}
	if orgSlotValue(store, testOrgA) != aValue || !reflect.DeepEqual(sessionIndexOrgs(t, store), index) {
		t.Fatal("the discard changed an organization slot or the index")
	}
}
