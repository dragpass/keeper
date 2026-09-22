// store_test.go — in-process guards for the storage contract. The parts that
// only two real processes can show (serialization, SIGKILL) live in
// chat_state_process_test.go.

package chatstate

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dragpass/keeper/config"
	"github.com/dragpass/keeper/internal/keystore/keychain"
)

const (
	testOwner   = "11111111-1111-4111-8111-111111111111"
	testConvA   = "22222222-2222-4222-8222-222222222222"
	testConvB   = "33333333-3333-4333-8333-333333333333"
	testClientA = "44444444-4444-4444-8444-444444444444"
)

var noWatermark = ServerWatermark{}

func newTestStore(t *testing.T) (*Store, *keychain.MemorySecretStore) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "config"))
	t.Setenv("APPDATA", filepath.Join(dir, "appdata"))
	secrets := keychain.NewMemorySecretStore()
	store, err := Open(secrets, testOwner)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(store.Close)
	return store, secrets
}

func sampleEntry(index uint64) OutboxEntry {
	return OutboxEntry{
		ClientMessageID: testClientA,
		Position:        Position{Epoch: 0, ChainIndex: index},
		IV:              bytes.Repeat([]byte{7}, ivBytes),
		Ciphertext:      []byte("sealed-bytes-for-the-wire"),
	}
}

func TestRootHonorsExplicitOverride(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(RootEnvVar, dir)
	got, err := Root()
	if err != nil || got != dir {
		t.Fatalf("Root() = %q, %v; want %q", got, err, dir)
	}
}

func TestReserveHandsOutDisjointPositions(t *testing.T) {
	store, _ := newTestStore(t)

	first, err := store.Reserve(testConvA, 2, noWatermark)
	if err != nil {
		t.Fatalf("first reserve: %v", err)
	}
	second, err := store.Reserve(testConvA, 3, noWatermark)
	if err != nil {
		t.Fatalf("second reserve: %v", err)
	}
	if first.FirstChainIndex != 0 || first.Count != 2 {
		t.Fatalf("first reservation = %+v", first)
	}
	if second.FirstChainIndex != 2 || second.Count != 3 {
		t.Fatalf("second reservation = %+v", second)
	}
	if second.Generation <= first.Generation {
		t.Fatalf("generation did not advance: %d then %d", first.Generation, second.Generation)
	}
}

func TestReserveSurvivesAFreshStore(t *testing.T) {
	store, secrets := newTestStore(t)
	if _, err := store.Reserve(testConvA, 4, noWatermark); err != nil {
		t.Fatalf("reserve: %v", err)
	}

	reopened, err := Open(secrets, testOwner)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()
	next, err := reopened.Reserve(testConvA, 1, noWatermark)
	if err != nil {
		t.Fatalf("reserve after reopen: %v", err)
	}
	if next.FirstChainIndex != 4 {
		t.Fatalf("reopened store handed out index %d, want 4", next.FirstChainIndex)
	}
}

func TestReserveRefusesARewoundFile(t *testing.T) {
	store, _ := newTestStore(t)
	if _, err := store.Reserve(testConvA, 1, noWatermark); err != nil {
		t.Fatalf("reserve: %v", err)
	}
	recordPath := store.paths(testConvA).record
	snapshot, err := os.ReadFile(recordPath)
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if _, err := store.Reserve(testConvA, 1, noWatermark); err != nil {
			t.Fatalf("reserve: %v", err)
		}
	}
	if err := os.WriteFile(recordPath, snapshot, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := store.Reserve(testConvA, 1, noWatermark); !errors.Is(err, ErrRekeyRequired) {
		t.Fatalf("reserve on a restored file = %v, want ErrRekeyRequired", err)
	}
	// The refusal latches: a second attempt does not find its way back in.
	if _, err := store.Reserve(testConvA, 1, noWatermark); !errors.Is(err, ErrRekeyRequired) {
		t.Fatalf("second reserve = %v, want ErrRekeyRequired", err)
	}
}

func TestReserveRefusesADeletedFileUnderALiveAnchor(t *testing.T) {
	store, _ := newTestStore(t)
	if _, err := store.Reserve(testConvA, 2, noWatermark); err != nil {
		t.Fatalf("reserve: %v", err)
	}
	if err := os.Remove(store.paths(testConvA).record); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Reserve(testConvA, 1, noWatermark); !errors.Is(err, ErrRekeyRequired) {
		t.Fatalf("reserve after deleting the file = %v, want ErrRekeyRequired", err)
	}
}

// The file and the anchor restored from the same moment is internally
// consistent, so only the server's watermark is left to notice it.
func TestServerWatermarkCatchesAFileAndAnchorRestoredTogether(t *testing.T) {
	store, secrets := newTestStore(t)
	if _, err := store.Reserve(testConvA, 1, noWatermark); err != nil {
		t.Fatalf("reserve: %v", err)
	}
	paths := store.paths(testConvA)
	recordSnapshot, err := os.ReadFile(paths.record)
	if err != nil {
		t.Fatal(err)
	}
	anchorSnapshot, err := secrets.Get(config.Service, anchorAccount(paths.tag))
	if err != nil {
		t.Fatal(err)
	}
	for range 5 {
		if _, err := store.Reserve(testConvA, 1, noWatermark); err != nil {
			t.Fatalf("reserve: %v", err)
		}
	}
	if err := os.WriteFile(paths.record, recordSnapshot, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := secrets.Set(config.Service, anchorAccount(paths.tag), anchorSnapshot); err != nil {
		t.Fatal(err)
	}

	// Restored alone the pair still validates — this is the gap the ADR keeps.
	if _, err := store.Reserve(testConvA, 1, noWatermark); err != nil {
		t.Fatalf("restored pair without a watermark = %v, want acceptance", err)
	}

	store2, secrets2 := newTestStore(t)
	if _, err := store2.Reserve(testConvB, 1, noWatermark); err != nil {
		t.Fatalf("reserve: %v", err)
	}
	paths2 := store2.paths(testConvB)
	record2, err := os.ReadFile(paths2.record)
	if err != nil {
		t.Fatal(err)
	}
	anchor2, err := secrets2.Get(config.Service, anchorAccount(paths2.tag))
	if err != nil {
		t.Fatal(err)
	}
	for range 5 {
		if _, err := store2.Reserve(testConvB, 1, noWatermark); err != nil {
			t.Fatalf("reserve: %v", err)
		}
	}
	if err := os.WriteFile(paths2.record, record2, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := secrets2.Set(config.Service, anchorAccount(paths2.tag), anchor2); err != nil {
		t.Fatal(err)
	}
	ahead := ServerWatermark{Epoch: 0, NextIndex: 6}
	if _, err := store2.Reserve(testConvB, 1, ahead); !errors.Is(err, ErrRekeyRequired) {
		t.Fatalf("reserve under a server watermark ahead of the file = %v, want ErrRekeyRequired", err)
	}
}

func TestServerWatermarkBehindTheAnchorLoses(t *testing.T) {
	store, _ := newTestStore(t)
	if _, err := store.Reserve(testConvA, 4, noWatermark); err != nil {
		t.Fatalf("reserve: %v", err)
	}
	if _, err := store.Reserve(testConvA, 1, ServerWatermark{NextIndex: 3}); err != nil {
		t.Fatalf("reserve under a watermark behind the file = %v", err)
	}
	// A server that now claims less than it already claimed must not talk this
	// device into handing out a position it already spent.
	got, err := store.Reserve(testConvA, 1, ServerWatermark{NextIndex: 1})
	if err != nil {
		t.Fatalf("reserve under a lower watermark = %v, want acceptance", err)
	}
	if got.FirstChainIndex != 5 {
		t.Fatalf("handed out index %d, want 5", got.FirstChainIndex)
	}
}

// A server that claims positions the file has never used is either lying or
// reporting a chain this device rewound away from. Either way it is refused.
func TestServerWatermarkAheadOfAFreshFileRefuses(t *testing.T) {
	store, _ := newTestStore(t)
	if _, err := store.Reserve(testConvA, 1, ServerWatermark{NextIndex: 3}); !errors.Is(err, ErrRekeyRequired) {
		t.Fatalf("reserve under a watermark ahead of the file = %v, want ErrRekeyRequired", err)
	}
}

func TestCommitOutboxReturnsTheStoredBytesOnRetry(t *testing.T) {
	store, _ := newTestStore(t)
	reservation, err := store.Reserve(testConvA, 1, noWatermark)
	if err != nil {
		t.Fatalf("reserve: %v", err)
	}
	entry := sampleEntry(reservation.FirstChainIndex)
	stored, created, err := store.CommitOutbox(testConvA, noWatermark, entry)
	if err != nil || !created {
		t.Fatalf("first commit: created=%v err=%v", created, err)
	}

	retry := entry
	retry.Ciphertext = []byte("a second encryption of the same message")
	retry.Position = Position{ChainIndex: reservation.FirstChainIndex + 1}
	again, created, err := store.CommitOutbox(testConvA, noWatermark, retry)
	if err != nil {
		t.Fatalf("retry commit: %v", err)
	}
	if created {
		t.Fatal("retry created a second outbox entry")
	}
	if !bytes.Equal(again.Ciphertext, stored.Ciphertext) || again.Position != stored.Position {
		t.Fatalf("retry returned %+v, want the stored %+v", again, stored)
	}

	read, err := store.ReadOutbox(testConvA, noWatermark, entry.ClientMessageID)
	if err != nil {
		t.Fatalf("read outbox: %v", err)
	}
	if !bytes.Equal(read.Ciphertext, entry.Ciphertext) || !bytes.Equal(read.IV, entry.IV) {
		t.Fatalf("read outbox returned %+v, want %+v", read, entry)
	}
}

func TestCommitOutboxRefusesAnUnreservedPosition(t *testing.T) {
	store, _ := newTestStore(t)
	if _, err := store.Reserve(testConvA, 1, noWatermark); err != nil {
		t.Fatalf("reserve: %v", err)
	}
	if _, _, err := store.CommitOutbox(testConvA, noWatermark, sampleEntry(9)); !errors.Is(err, ErrPositionNotReserved) {
		t.Fatalf("commit at an unreserved position = %v, want ErrPositionNotReserved", err)
	}
}

func TestCommitOutboxRefusesATakenPosition(t *testing.T) {
	store, _ := newTestStore(t)
	if _, err := store.Reserve(testConvA, 2, noWatermark); err != nil {
		t.Fatalf("reserve: %v", err)
	}
	if _, _, err := store.CommitOutbox(testConvA, noWatermark, sampleEntry(0)); err != nil {
		t.Fatalf("first commit: %v", err)
	}
	second := sampleEntry(0)
	second.ClientMessageID = "55555555-5555-4555-8555-555555555555"
	second.Ciphertext = []byte("a different plaintext at the same position")
	if _, _, err := store.CommitOutbox(testConvA, noWatermark, second); !errors.Is(err, ErrPositionTaken) {
		t.Fatalf("second plaintext at one position = %v, want ErrPositionTaken", err)
	}
}

func TestReadOutboxReportsAMissingEntry(t *testing.T) {
	store, _ := newTestStore(t)
	if _, err := store.ReadOutbox(testConvA, noWatermark, testClientA); !errors.Is(err, ErrNotFound) {
		t.Fatalf("read of a missing entry = %v, want ErrNotFound", err)
	}
}

func TestMarkReceivedAdvancesOnce(t *testing.T) {
	store, _ := newTestStore(t)
	pos := Position{Epoch: 0, ChainIndex: 3}
	first, gen1, err := store.MarkReceived(testConvA, noWatermark, pos)
	if err != nil || !first {
		t.Fatalf("first delivery: first=%v err=%v", first, err)
	}
	again, gen2, err := store.MarkReceived(testConvA, noWatermark, pos)
	if err != nil {
		t.Fatalf("redelivery: %v", err)
	}
	if again {
		t.Fatal("redelivery reported as a first delivery")
	}
	if gen2 != gen1 {
		t.Fatalf("redelivery advanced the generation from %d to %d", gen1, gen2)
	}
}

func TestStrayTempFileIsNeverLoadedAndIsRemoved(t *testing.T) {
	store, _ := newTestStore(t)
	if _, err := store.Reserve(testConvA, 1, noWatermark); err != nil {
		t.Fatalf("reserve: %v", err)
	}
	paths := store.paths(testConvA)
	stray := filepath.Join(paths.dir, tempPrefix+"halfwritten")
	if err := os.WriteFile(stray, []byte("torn"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Reserve(testConvA, 1, noWatermark); err != nil {
		t.Fatalf("reserve with a stray temp file present: %v", err)
	}
	if _, err := os.Stat(stray); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stray temp file survived: %v", err)
	}
}

func TestAnUnreadableRecordDoesNotBlockOtherConversations(t *testing.T) {
	store, _ := newTestStore(t)
	if _, err := store.Reserve(testConvA, 1, noWatermark); err != nil {
		t.Fatalf("reserve A: %v", err)
	}
	if err := os.WriteFile(store.paths(testConvA).record, []byte("corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Reserve(testConvA, 1, noWatermark); err == nil {
		t.Fatal("a corrupt record was accepted")
	}
	if _, err := store.Reserve(testConvB, 1, noWatermark); err != nil {
		t.Fatalf("a corrupt conversation blocked another one: %v", err)
	}
}

func TestSealedRecordDoesNotExposeItsContents(t *testing.T) {
	store, _ := newTestStore(t)
	if _, err := store.Reserve(testConvA, 1, noWatermark); err != nil {
		t.Fatalf("reserve: %v", err)
	}
	sealed, err := os.ReadFile(store.paths(testConvA).record)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte(testConvA)) || bytes.Contains(sealed, []byte(testOwner)) {
		t.Fatal("the sealed record carries its conversation or owner id in the clear")
	}
	if strings.Contains(filepath.Base(store.paths(testConvA).record), testConvA) {
		t.Fatal("the file name carries the conversation id")
	}
	info, err := os.Stat(store.paths(testConvA).record)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("record permissions = %o, want 600", perm)
	}
}

// The AAD binds the conversation, so a file moved between conversations of the
// same owner does not open.
func TestARecordDoesNotOpenAsAnotherConversation(t *testing.T) {
	store, _ := newTestStore(t)
	if _, err := store.Reserve(testConvA, 1, noWatermark); err != nil {
		t.Fatalf("reserve: %v", err)
	}
	sealed, err := os.ReadFile(store.paths(testConvA).record)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(store.paths(testConvB).record, sealed, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.readRecord(store.paths(testConvB), testConvB); !errors.Is(err, errSealedRecordMalformed) {
		t.Fatalf("a foreign conversation's record opened: %v", err)
	}
}

// The generation guard is the belt behind the lock's braces: it fires when the
// file changed between the read and the write inside one locked section, which
// only happens if the lock stopped working.
func TestWriteRefusesAStaleRecord(t *testing.T) {
	store, _ := newTestStore(t)
	paths := store.paths(testConvA)
	if _, err := store.Reserve(testConvA, 1, noWatermark); err != nil {
		t.Fatalf("reserve: %v", err)
	}
	stale, err := store.readRecord(paths, testConvA)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	staleGeneration := stale.Generation
	if _, err := store.Reserve(testConvA, 1, noWatermark); err != nil {
		t.Fatalf("reserve: %v", err)
	}
	stale.NextIndex = 99
	if err := store.writeRecord(paths, stale, staleGeneration); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale write = %v, want ErrConflict", err)
	}
}

// GroupState is the seat the MLS layer will use. Nothing on the wire reads or
// writes it, so this is what keeps the field honest until that layer exists.
func TestGroupStateRoundTripsThroughTheSealedFile(t *testing.T) {
	store, _ := newTestStore(t)
	paths := store.paths(testConvA)
	if _, err := store.Reserve(testConvA, 1, noWatermark); err != nil {
		t.Fatalf("reserve: %v", err)
	}
	rec, err := store.readRecord(paths, testConvA)
	if err != nil {
		t.Fatal(err)
	}
	blob := bytes.Repeat([]byte("mls-group-state"), 64)
	loaded := rec.Generation
	rec.GroupState = blob
	if err := store.writeRecord(paths, rec, loaded); err != nil {
		t.Fatalf("write: %v", err)
	}
	sealed, err := os.ReadFile(paths.record)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, blob) {
		t.Fatal("the group state is on disk in the clear")
	}
	back, err := store.readRecord(paths, testConvA)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back.GroupState, blob) {
		t.Fatal("the group state did not round-trip")
	}
}

func TestPurgeRemovesEverythingAndMakesRestoresUseless(t *testing.T) {
	store, secrets := newTestStore(t)
	for _, conv := range []string{testConvA, testConvB} {
		if _, err := store.Reserve(conv, 1, noWatermark); err != nil {
			t.Fatalf("reserve %s: %v", conv, err)
		}
	}
	paths := store.paths(testConvA)
	sealed, err := os.ReadFile(paths.record)
	if err != nil {
		t.Fatal(err)
	}
	ownerDir := store.ownerDir()

	removed, err := Purge(secrets, testOwner)
	if err != nil {
		t.Fatalf("purge: %v", err)
	}
	if removed != 2 {
		t.Fatalf("purge removed %d conversations, want 2", removed)
	}
	if _, err := os.Stat(ownerDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("owner directory survived the purge: %v", err)
	}
	if _, err := secrets.Get(config.Service, sealKeyAccount(testOwner)); !errors.Is(err, keychain.ErrSecretNotFound) {
		t.Fatalf("seal key survived the purge: %v", err)
	}
	if _, err := secrets.Get(config.Service, anchorAccount(paths.tag)); !errors.Is(err, keychain.ErrSecretNotFound) {
		t.Fatalf("anchor survived the purge: %v", err)
	}

	// Restoring the old file after a purge is useless: the seal key it was
	// sealed under is gone, so the replacement cannot open it.
	fresh, err := Open(secrets, testOwner)
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	restored := fresh.paths(testConvA)
	if err := os.MkdirAll(restored.dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(restored.record, sealed, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := fresh.readRecord(restored, testConvA); err == nil {
		t.Fatal("a pre-purge record opened under the replacement seal key")
	}
}

func TestPurgeWithoutAnySealKeyIsANoOp(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "config"))
	t.Setenv("APPDATA", filepath.Join(dir, "appdata"))
	removed, err := Purge(keychain.NewMemorySecretStore(), testOwner)
	if err != nil || removed != 0 {
		t.Fatalf("purge on an untouched account = %d, %v", removed, err)
	}
}

func TestAnUnreadableAnchorIsTreatedAsARewind(t *testing.T) {
	store, secrets := newTestStore(t)
	if _, err := store.Reserve(testConvA, 1, noWatermark); err != nil {
		t.Fatalf("reserve: %v", err)
	}
	tag := store.paths(testConvA).tag
	if err := secrets.Set(config.Service, anchorAccount(tag), "not json"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Reserve(testConvA, 1, noWatermark); !errors.Is(err, ErrRekeyRequired) {
		t.Fatalf("reserve under an unreadable anchor = %v, want ErrRekeyRequired", err)
	}
}

func TestOutboxRingDropsTheOldestEntry(t *testing.T) {
	store, _ := newTestStore(t)
	if _, err := store.Reserve(testConvA, MaxReserveCount, noWatermark); err != nil {
		t.Fatalf("reserve: %v", err)
	}
	if _, err := store.Reserve(testConvA, MaxReserveCount, noWatermark); err != nil {
		t.Fatalf("reserve: %v", err)
	}
	firstID := ""
	for i := range OutboxCapacity + 1 {
		entry := sampleEntry(uint64(i))
		entry.ClientMessageID = clientID(i)
		if i == 0 {
			firstID = entry.ClientMessageID
		}
		if _, _, err := store.CommitOutbox(testConvA, noWatermark, entry); err != nil {
			t.Fatalf("commit %d: %v", i, err)
		}
	}
	if _, err := store.ReadOutbox(testConvA, noWatermark, firstID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("the oldest outbox entry survived the ring: %v", err)
	}
	if _, err := store.ReadOutbox(testConvA, noWatermark, clientID(OutboxCapacity)); err != nil {
		t.Fatalf("the newest outbox entry is missing: %v", err)
	}
}

func clientID(i int) string {
	return "66666666-6666-4666-8666-" + string([]byte{
		'0' + byte(i/100000%10), '0' + byte(i/10000%10), '0' + byte(i/1000%10),
		'0' + byte(i/100%10), '0' + byte(i/10%10), '0' + byte(i%10),
	}) + "000000"
}

func TestAnchorJSONStaysSmallEnoughForEveryKeyring(t *testing.T) {
	raw, err := json.Marshal(Anchor{
		Generation: 1 << 40, ReservedBefore: 1 << 40, Epoch: 1 << 40,
		WatermarkEpoch: 1 << 40, WatermarkNextIndex: 1 << 40, NeedsRekey: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Windows Credential Manager caps an entry around 2.5 KB. The anchor is in
	// the keyring because it is small; a change that stops being small is a
	// design change.
	if len(raw) > 256 {
		t.Fatalf("anchor JSON is %d bytes: %s", len(raw), raw)
	}
}
