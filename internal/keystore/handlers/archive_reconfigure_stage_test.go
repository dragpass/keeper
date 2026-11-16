// archive_reconfigure_stage_test.go — archive_reconfigure_stage (lv90 K1).
//
// A legacy quorum reconfiguration stages its new org archive key in a slot
// of its own. The active key and a rotation stage are never touched, and the
// org's reconfiguration journal names one operation: a stage for another
// operation is refused instead of replacing it.

package handlers

import (
	"encoding/json"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dragpass/keeper/config"
	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/testdouble"
)

const (
	reconfigOpA = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
	reconfigOpB = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
)

func stageReconfiguration(deps Deps, orgID, operationID string) proto.BaseResponse {
	return HandleArchiveReconfigureStage(deps, proto.ArchiveReconfigureStageRequest{OrgID: orgID, OperationID: operationID})
}

// slotEntries returns the stored values of the given slots' accounts.
func slotEntries(store *testdouble.MemorySecretStore, slots ...keychain.ArchiveKeySlot) map[string]string {
	out := map[string]string{}
	for _, slot := range slots {
		for _, account := range []string{slot.PrivateAccount, slot.PublicAccount} {
			if value, err := store.Get(config.Service, account); err == nil {
				out[account] = value
			}
		}
	}
	return out
}

func readReconfigurationJournal(t *testing.T, store keychain.SecretStore, orgID string) map[string]any {
	t.Helper()
	raw, err := store.Get(config.Service, config.OrgArchiveReconfigurationJournalPrefix+orgID)
	if err != nil {
		t.Fatalf("reconfiguration journal: %v", err)
	}
	var journal map[string]any
	if err := json.Unmarshal([]byte(raw), &journal); err != nil {
		t.Fatal(err)
	}
	return journal
}

// The new key goes to the org's reconfiguration slot; the active key and the
// rotation stage keep exactly what they held, and the journal records the
// operation kind, the operation and the staged key.
func TestArchiveReconfigureStage_StagesWithoutTouchingActiveOrRotationSlots(t *testing.T) {
	deps, _, store := newTestDeps(t)
	generateFor(t, deps, testOrgA)
	beginOrg(t, deps, testOrgA)
	others := []keychain.ArchiveKeySlot{
		keychain.OrgArchiveActiveSlot(testOrgA), keychain.OrgArchiveStagingSlot(testOrgA),
		keychain.OrgArchiveActiveSlot(""), keychain.OrgArchiveStagingSlot(""),
	}
	before := slotEntries(store, others...)

	resp := stageReconfiguration(deps, testOrgA, reconfigOpA)
	if !resp.Success {
		t.Fatalf("stage: %+v", resp)
	}
	data := resp.Data.(proto.ArchiveReconfigureStageResponseData)
	if !reflect.DeepEqual(before, slotEntries(store, others...)) {
		t.Fatal("stage changed the active key or a rotation stage")
	}
	slot := keychain.OrgArchiveReconfigurationSlot(testOrgA)
	priv, _ := slot.GetPrivate(store)
	pub, _ := slot.GetPublic(store)
	parsed, err := crypto.ParsePrivateKey(priv)
	if err != nil {
		t.Fatalf("staged private key: %v", err)
	}
	derived, _ := crypto.PublicKeyToPEM(&parsed.PublicKey)
	if derived != pub || pub != data.PublicKey || data.Fingerprint != fingerprintBase64Public(pub) {
		t.Fatal("the answered key is not the staged pair")
	}
	journal := readReconfigurationJournal(t, store, testOrgA)
	if journal["kind"] != "reconfiguration" || journal["operation_id"] != reconfigOpA ||
		journal["org_id"] != testOrgA || journal["target_key_fingerprint"] != data.Fingerprint {
		t.Fatalf("journal: %+v", journal)
	}
}

// Both IDs are required; a refused request writes nothing.
func TestArchiveReconfigureStage_RequiresOrgAndOperation(t *testing.T) {
	deps, _, store := newTestDeps(t)
	for name, req := range map[string]proto.ArchiveReconfigureStageRequest{
		"no org":              {OperationID: reconfigOpA},
		"malformed org":       {OrgID: "x", OperationID: reconfigOpA},
		"no operation":        {OrgID: testOrgA},
		"malformed operation": {OrgID: testOrgA, OperationID: "x"},
	} {
		before := store.Snapshot()
		resp := HandleArchiveReconfigureStage(deps, req)
		if resp.Success || resp.ErrorCode != string(errs.ErrCodeValidation) {
			t.Fatalf("%s: %+v", name, resp)
		}
		if !reflect.DeepEqual(before, store.Snapshot()) {
			t.Fatalf("%s changed the keychain", name)
		}
	}
}

// The org's journal names one operation. A stage for another operation, or a
// journal of another kind or one that does not parse, is refused and leaves
// the staged key and the journal as they were.
func TestArchiveReconfigureStage_RefusesAnotherOperationsJournal(t *testing.T) {
	for name, journal := range map[string]string{
		"another operation": "",
		"another kind":      `{"kind":"activation","operation_id":"` + reconfigOpB + `","org_id":"` + testOrgA + `"}`,
		"unreadable":        `{`,
	} {
		t.Run(name, func(t *testing.T) {
			deps, _, store := newTestDeps(t)
			if journal == "" {
				if resp := stageReconfiguration(deps, testOrgA, reconfigOpA); !resp.Success {
					t.Fatalf("first stage: %+v", resp)
				}
			} else if err := store.Set(config.Service, config.OrgArchiveReconfigurationJournalPrefix+testOrgA, journal); err != nil {
				t.Fatal(err)
			}
			before := store.Snapshot()
			resp := stageReconfiguration(deps, testOrgA, reconfigOpB)
			if resp.Success || resp.ErrorCode != string(errs.ErrCodeArchiveReconfigurationPending) || resp.Data != nil {
				t.Fatalf("stage over %s: %+v", name, resp)
			}
			if !reflect.DeepEqual(before, store.Snapshot()) {
				t.Fatal("a refused stage changed the keychain")
			}
		})
	}
}

// A retry of the same operation (the App lost the answer) gets the key it
// staged, not a new one the server was never told about.
func TestArchiveReconfigureStage_RetryReturnsTheStagedKey(t *testing.T) {
	deps, _, store := newTestDeps(t)
	first := stageReconfiguration(deps, testOrgA, reconfigOpA)
	if !first.Success {
		t.Fatalf("first stage: %+v", first)
	}
	before := store.Snapshot()
	retry := stageReconfiguration(deps, testOrgA, reconfigOpA)
	if !retry.Success || !reflect.DeepEqual(first.Data, retry.Data) {
		t.Fatalf("retry: %+v", retry)
	}
	if !reflect.DeepEqual(before, store.Snapshot()) {
		t.Fatal("a retry changed the keychain")
	}
}

// Key material in the reconfiguration slot with no journal names no
// operation; it is refused and kept, never overwritten.
func TestArchiveReconfigureStage_RefusesAnUnjournaledSlot(t *testing.T) {
	for _, half := range []string{"private", "public"} {
		t.Run(half, func(t *testing.T) {
			deps, _, store := newTestDeps(t)
			slot := keychain.OrgArchiveReconfigurationSlot(testOrgA)
			other, _ := crypto.GenerateRSAKeyPair()
			if half == "private" {
				_ = slot.SavePrivate(store, other.PrivateKey)
			} else {
				_ = slot.SavePublic(store, other.PublicKey)
			}
			before := store.Snapshot()
			resp := stageReconfiguration(deps, testOrgA, reconfigOpA)
			if resp.Success || resp.ErrorCode != string(errs.ErrCodeArchiveKeySlotIncomplete) {
				t.Fatalf("stage over an unjournaled %s half: %+v", half, resp)
			}
			if !reflect.DeepEqual(before, store.Snapshot()) {
				t.Fatal("a refused stage changed the keychain")
			}
		})
	}
}

// A failed write answers no key and leaves a state the same operation's retry
// completes: no unjournaled key, and no journal naming a key that is absent.
func TestArchiveReconfigureStage_FailedWriteIsRetriedBySameOperation(t *testing.T) {
	slot := keychain.OrgArchiveReconfigurationSlot(testOrgA)
	for name, account := range map[string]string{
		"private write": slot.PrivateAccount,
		"public write":  slot.PublicAccount,
		"journal write": config.OrgArchiveReconfigurationJournalPrefix + testOrgA,
	} {
		t.Run(name, func(t *testing.T) {
			deps, _, mem := newTestDeps(t)
			deps.Store = failOrgPublicStore{MemorySecretStore: mem, account: account}
			failed := stageReconfiguration(deps, testOrgA, reconfigOpA)
			if failed.Success || failed.Data != nil {
				t.Fatalf("failed %s answered: %+v", name, failed)
			}
			if pub, hasPriv, _ := slotHalves(mem, slot); pub != "" || hasPriv {
				if _, err := mem.Get(config.Service, config.OrgArchiveReconfigurationJournalPrefix+testOrgA); err != nil {
					t.Fatal("key material was left without a journal")
				}
			}
			deps.Store = mem
			retry := stageReconfiguration(deps, testOrgA, reconfigOpA)
			if !retry.Success {
				t.Fatalf("retry after a failed %s: %+v", name, retry)
			}
			pub, _ := slot.GetPublic(mem)
			if retry.Data.(proto.ArchiveReconfigureStageResponseData).PublicKey != pub {
				t.Fatal("the retry answered a key that is not staged")
			}
		})
	}
}

// lockWatchStore records a write made outside the fake process lock.
type lockWatchStore struct {
	*testdouble.MemorySecretStore
	locked         *bool
	unlockedWrites int
}

func (s *lockWatchStore) Set(service, account, value string) error {
	if !*s.locked {
		s.unlockedWrites++
	}
	return s.MemorySecretStore.Set(service, account, value)
}

// The lv96 rule for org archive slot writers: the RSA pair is generated
// outside the keychain process lock, and every write runs inside it.
func TestArchiveReconfigureStage_WritesUnderTheProcessLockAndGeneratesOutside(t *testing.T) {
	deps, _, mem := newTestDeps(t)
	locked := false
	store := &lockWatchStore{MemorySecretStore: mem, locked: &locked}
	deps.Store = store
	keygenUnderLock := false
	restoreLock, restoreKeygen := archiveSlotProcessLock, archiveKeyPairGenerator
	t.Cleanup(func() { archiveSlotProcessLock, archiveKeyPairGenerator = restoreLock, restoreKeygen })
	archiveSlotProcessLock = func(_ keychain.SecretStore, fn func() error) error {
		locked = true
		defer func() { locked = false }()
		return fn()
	}
	archiveKeyPairGenerator = func() (*crypto.KeyPair, error) {
		keygenUnderLock = keygenUnderLock || locked
		return crypto.GenerateRSAKeyPair()
	}
	if resp := stageReconfiguration(deps, testOrgA, reconfigOpA); !resp.Success {
		t.Fatalf("stage: %+v", resp)
	}
	if keygenUnderLock {
		t.Fatal("the key pair was generated under the keychain process lock")
	}
	if store.unlockedWrites != 0 {
		t.Fatalf("%d writes ran outside the keychain process lock", store.unlockedWrites)
	}
}

// Another Keeper process may stage between this call's first read and its
// lock. The re-check under the lock keeps that stage and refuses this one.
func TestArchiveReconfigureStage_RechecksTheJournalUnderTheLock(t *testing.T) {
	deps, _, store := newTestDeps(t)
	restoreLock := archiveSlotProcessLock
	t.Cleanup(func() { archiveSlotProcessLock = restoreLock })
	var otherProcess proto.BaseResponse
	archiveSlotProcessLock = func(s keychain.SecretStore, fn func() error) error {
		archiveSlotProcessLock = restoreLock
		other := mustRSA(t)
		otherProcess = writeReconfigurationStage(deps, proto.ArchiveReconfigureStageRequest{OrgID: testOrgA, OperationID: reconfigOpB}, other.priv, other.pub)
		return fn()
	}
	resp := stageReconfiguration(deps, testOrgA, reconfigOpA)
	if !otherProcess.Success {
		t.Fatalf("other process stage: %+v", otherProcess)
	}
	if resp.Success || resp.ErrorCode != string(errs.ErrCodeArchiveReconfigurationPending) {
		t.Fatalf("stage after another process staged: %+v", resp)
	}
	if journal := readReconfigurationJournal(t, store, testOrgA); journal["operation_id"] != reconfigOpB {
		t.Fatal("the other process's journal was replaced")
	}
	pub, _ := keychain.OrgArchiveReconfigurationSlot(testOrgA).GetPublic(store)
	if pub != otherProcess.Data.(proto.ArchiveReconfigureStageResponseData).PublicKey {
		t.Fatal("the other process's staged key was replaced")
	}
}

type rsaPEMs struct {
	priv []byte
	pub  string
}

func mustRSA(t *testing.T) rsaPEMs {
	t.Helper()
	kp, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	return rsaPEMs{priv: []byte(kp.PrivateKey), pub: kp.PublicKey}
}

// reconfigJournalBarrierStore parks the first journal write until release,
// so a second stage is armed while the first is inside its writes.
type reconfigJournalBarrierStore struct {
	keychain.SecretStore
	writes  atomic.Int32
	entered chan struct{}
	release chan struct{}
}

func (s *reconfigJournalBarrierStore) Set(service, account, value string) error {
	if strings.HasPrefix(account, config.OrgArchiveReconfigurationJournalPrefix) && s.writes.Add(1) == 1 {
		close(s.entered)
		<-s.release
	}
	return s.SecretStore.Set(service, account, value)
}

// Two stages for one org run one at a time: a retry of the same operation
// gets the first call's key, and a stage for another operation is refused.
// Neither replaces the key the first call staged.
func TestArchiveReconfigureStage_ConcurrentStagesActOnce(t *testing.T) {
	for name, secondOp := range map[string]string{"same operation": reconfigOpA, "another operation": reconfigOpB} {
		t.Run(name, func(t *testing.T) {
			deps, _, mem := newTestDeps(t)
			gate := &reconfigJournalBarrierStore{SecretStore: mem, entered: make(chan struct{}), release: make(chan struct{})}
			var releaseOnce sync.Once
			release := func() { releaseOnce.Do(func() { close(gate.release) }) }
			t.Cleanup(release)
			deps.Store = gate
			first := make(chan proto.BaseResponse, 1)
			second := make(chan proto.BaseResponse, 1)
			go func() { first <- stageReconfiguration(deps, testOrgA, reconfigOpA) }()
			select {
			case <-gate.entered:
			case <-time.After(5 * time.Second):
				t.Fatal("the first stage did not reach its journal write")
			}
			go func() { second <- stageReconfiguration(deps, testOrgA, secondOp) }()
			// Give the second stage every chance to interleave.
			select {
			case r := <-second:
				second <- r
			case <-time.After(150 * time.Millisecond):
			}
			release()
			a, b := <-first, <-second
			if !a.Success {
				t.Fatalf("first stage: %+v", a)
			}
			staged, _ := keychain.OrgArchiveReconfigurationSlot(testOrgA).GetPublic(mem)
			if staged != a.Data.(proto.ArchiveReconfigureStageResponseData).PublicKey {
				t.Fatal("the first stage's key was replaced")
			}
			if secondOp == reconfigOpA {
				if !b.Success || !reflect.DeepEqual(a.Data, b.Data) {
					t.Fatalf("same-operation retry: %+v", b)
				}
			} else if b.Success || b.ErrorCode != string(errs.ErrCodeArchiveReconfigurationPending) {
				t.Fatalf("another operation's stage: %+v", b)
			}
		})
	}
}

// The lv96 rule: every org archive slot writer holds
// archiveSplitPreparationMu for the whole call, so a stage never interleaves
// with a generate, a rotation, a split, finalize or abandon in this process.
func TestArchiveReconfigureStage_HoldsTheOrgArchiveWriterMutex(t *testing.T) {
	deps, _, store := newTestDeps(t)
	archiveSplitPreparationMu.Lock()
	locked := true
	unlock := func() {
		if locked {
			locked = false
			archiveSplitPreparationMu.Unlock()
		}
	}
	t.Cleanup(unlock)
	before := store.Snapshot()
	done := make(chan proto.BaseResponse, 1)
	go func() { done <- stageReconfiguration(deps, testOrgA, reconfigOpA) }()
	select {
	case resp := <-done:
		t.Fatalf("stage ran while another org archive writer held the mutex: %+v", resp)
	case <-time.After(200 * time.Millisecond):
	}
	if !reflect.DeepEqual(before, store.Snapshot()) {
		t.Fatal("stage wrote while another org archive writer held the mutex")
	}
	unlock()
	select {
	case resp := <-done:
		if !resp.Success {
			t.Fatalf("stage after the mutex was released: %+v", resp)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("stage did not finish after the mutex was released")
	}
}

// An open reconfiguration owns the org's next key. archive_key_generate must
// not create an active key beside it (lv96 orgArchiveSlotDecision rule), even
// when only the journal of an interrupted stage is left.
func TestArchiveKeyGenerate_RefusesWhileAReconfigurationIsStaged(t *testing.T) {
	for _, state := range []string{"staged key", "journal only"} {
		t.Run(state, func(t *testing.T) {
			deps, _, store := newTestDeps(t)
			if state == "staged key" {
				if resp := stageReconfiguration(deps, testOrgA, reconfigOpA); !resp.Success {
					t.Fatalf("stage: %+v", resp)
				}
			} else if err := writeArchiveReconfigurationJournal(store, archiveReconfigurationJournal{Kind: archiveOperationKindReconfiguration, OperationID: reconfigOpA, OrgID: testOrgA}); err != nil {
				t.Fatal(err)
			}
			before := store.Snapshot()
			resp := HandleArchiveKeyGenerate(deps, proto.ArchiveKeyGenerateRequest{OrgID: testOrgA})
			if resp.Success || resp.ErrorCode != string(errs.ErrCodeArchiveReconfigurationPending) || resp.Data != nil {
				t.Fatalf("generate during a reconfiguration: %+v", resp)
			}
			if !reflect.DeepEqual(before, store.Snapshot()) {
				t.Fatal("a refused generate changed the keychain")
			}
			// Another org on the device is unaffected.
			generateFor(t, deps, testOrgB)
		})
	}
}

// The staged private key never appears in the answer or the log, on success
// or on a refusal.
func TestArchiveReconfigureStage_NoPrivateMaterialInAnswerOrLog(t *testing.T) {
	deps, log, store := newTestDeps(t)
	ok := stageReconfiguration(deps, testOrgA, reconfigOpA)
	refused := stageReconfiguration(deps, testOrgA, reconfigOpB)
	priv, _ := keychain.OrgArchiveReconfigurationSlot(testOrgA).GetPrivate(store)
	body := priv[strings.Index(priv, "\n")+1 : strings.Index(priv, "\n")+41]
	for _, resp := range []proto.BaseResponse{ok, refused} {
		raw, _ := json.Marshal(resp)
		if strings.Contains(string(raw), "PRIVATE KEY") || strings.Contains(string(raw), body) {
			t.Fatal("an answer carried private key material")
		}
	}
	for _, msg := range log.Messages() {
		if strings.Contains(msg, "PRIVATE KEY") || strings.Contains(msg, body) {
			t.Fatalf("the log carried private key material: %q", msg)
		}
	}
}
