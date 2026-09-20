// peer_key_pin_test.go — pin storage, index chunking, and the size bounds the
// smallest platform keyring imposes.
//
// Everything runs against MemorySecretStore, which is the same SecretStore
// interface the platform keyring implements, so these tests walk the production
// path rather than a stand-in for it.

package keychain

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/dragpass/keeper/config"
)

const (
	testOwnerA = "11111111-1111-4111-8111-111111111111"
	testOwnerB = "22222222-2222-4222-8222-222222222222"
	testPeer1  = "33333333-3333-4333-8333-333333333333"
	testPeer2  = "44444444-4444-4444-8444-444444444444"
)

func testPin(fingerprint string, state PeerKeyPinState) PeerKeyPin {
	return PeerKeyPin{
		Fingerprint: fingerprint,
		State:       state,
		FirstSeenAt: 1758240000,
		LastSeenAt:  1758246000,
	}
}

func fingerprintOfLen(c byte) string {
	return strings.Repeat(string(c), 64)
}

func TestPeerKeyPin_SaveGetDelete(t *testing.T) {
	store := NewMemorySecretStore()

	if _, err := GetPeerKeyPin(store, testOwnerA, testPeer1); !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("missing pin error = %v, want ErrSecretNotFound", err)
	}

	pin := testPin(fingerprintOfLen('a'), PeerKeyPinStateTOFU)
	if err := SavePeerKeyPin(store, testOwnerA, testPeer1, pin); err != nil {
		t.Fatalf("SavePeerKeyPin: %v", err)
	}

	got, err := GetPeerKeyPin(store, testOwnerA, testPeer1)
	if err != nil {
		t.Fatalf("GetPeerKeyPin: %v", err)
	}
	if got.Fingerprint != pin.Fingerprint || got.State != PeerKeyPinStateTOFU {
		t.Fatalf("pin = %+v, want fingerprint %q state tofu", got, pin.Fingerprint)
	}
	if got.V != PeerKeyPinVersion {
		t.Fatalf("pin.V = %d, want %d (Save stamps the schema version)", got.V, PeerKeyPinVersion)
	}
	if got.VerifiedAt != 0 || got.LastRotationFingerprint != "" {
		t.Fatalf("unset optional fields came back set: %+v", got)
	}

	forgotten, err := DeletePeerKeyPin(store, testOwnerA, testPeer1)
	if err != nil {
		t.Fatalf("DeletePeerKeyPin: %v", err)
	}
	if !forgotten {
		t.Fatal("DeletePeerKeyPin reported nothing forgotten for an existing pin")
	}

	// Idempotent: a second delete is a successful no-op reporting false.
	forgotten, err = DeletePeerKeyPin(store, testOwnerA, testPeer1)
	if err != nil {
		t.Fatalf("second DeletePeerKeyPin: %v", err)
	}
	if forgotten {
		t.Fatal("second DeletePeerKeyPin reported a pin forgotten")
	}
}

func TestPeerKeyPin_AccountNameLayout(t *testing.T) {
	if got, want := PeerKeyPinAccount(testOwnerA, testPeer1), config.PeerKeyPinPrefix+testOwnerA+":"+testPeer1; got != want {
		t.Fatalf("PeerKeyPinAccount = %q, want %q", got, want)
	}
	if got, want := PeerKeyPinIndexAccount(testOwnerA, 3), config.PeerKeyPinIndexPrefix+testOwnerA+":3"; got != want {
		t.Fatalf("PeerKeyPinIndexAccount = %q, want %q", got, want)
	}
}

func TestPeerKeyPin_ListFollowsIndex(t *testing.T) {
	store := NewMemorySecretStore()

	entries, err := ListPeerKeyPins(store, testOwnerA)
	if err != nil {
		t.Fatalf("ListPeerKeyPins on empty store: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("empty store listed %d pins", len(entries))
	}

	if err := SavePeerKeyPin(store, testOwnerA, testPeer1, testPin(fingerprintOfLen('a'), PeerKeyPinStateTOFU)); err != nil {
		t.Fatalf("SavePeerKeyPin peer1: %v", err)
	}
	if err := SavePeerKeyPin(store, testOwnerA, testPeer2, testPin(fingerprintOfLen('b'), PeerKeyPinStateVerified)); err != nil {
		t.Fatalf("SavePeerKeyPin peer2: %v", err)
	}
	// Re-saving must not duplicate the index entry.
	if err := SavePeerKeyPin(store, testOwnerA, testPeer1, testPin(fingerprintOfLen('c'), PeerKeyPinStateRotated)); err != nil {
		t.Fatalf("re-SavePeerKeyPin peer1: %v", err)
	}

	entries, err = ListPeerKeyPins(store, testOwnerA)
	if err != nil {
		t.Fatalf("ListPeerKeyPins: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("listed %d pins, want 2 (%+v)", len(entries), entries)
	}
	if entries[0].AccountID != testPeer1 || entries[0].Pin.Fingerprint != fingerprintOfLen('c') {
		t.Fatalf("entry 0 = %+v, want peer1 with the re-saved fingerprint", entries[0])
	}
	if entries[1].AccountID != testPeer2 || entries[1].Pin.State != PeerKeyPinStateVerified {
		t.Fatalf("entry 1 = %+v, want peer2 verified", entries[1])
	}
}

// A delete that removed the record but not the index entry must not make the
// listing fail — the stale id is dropped and the chunk rewritten.
func TestPeerKeyPin_ListDropsStaleIndexEntry(t *testing.T) {
	store := NewMemorySecretStore()
	if err := SavePeerKeyPin(store, testOwnerA, testPeer1, testPin(fingerprintOfLen('a'), PeerKeyPinStateTOFU)); err != nil {
		t.Fatalf("SavePeerKeyPin: %v", err)
	}
	if err := SavePeerKeyPin(store, testOwnerA, testPeer2, testPin(fingerprintOfLen('b'), PeerKeyPinStateTOFU)); err != nil {
		t.Fatalf("SavePeerKeyPin: %v", err)
	}
	// Remove the record behind the store's back, leaving the index entry.
	if err := store.Delete(config.Service, PeerKeyPinAccount(testOwnerA, testPeer1)); err != nil {
		t.Fatalf("raw delete: %v", err)
	}

	entries, err := ListPeerKeyPins(store, testOwnerA)
	if err != nil {
		t.Fatalf("ListPeerKeyPins: %v", err)
	}
	if len(entries) != 1 || entries[0].AccountID != testPeer2 {
		t.Fatalf("listed %+v, want only peer2", entries)
	}

	raw, err := store.Get(config.Service, PeerKeyPinIndexAccount(testOwnerA, 0))
	if err != nil {
		t.Fatalf("read index chunk 0: %v", err)
	}
	if strings.Contains(raw, testPeer1) {
		t.Fatalf("stale id still in the index chunk: %s", raw)
	}
}

// The index is chunked at exactly PeerKeyPinIndexChunkSize ids, and a delete
// never renumbers: chunk 0 stays chunk 0 even when it is emptied.
func TestPeerKeyPin_IndexChunkBoundary(t *testing.T) {
	store := NewMemorySecretStore()

	ids := make([]string, PeerKeyPinIndexChunkSize+1)
	for i := range ids {
		ids[i] = fmt.Sprintf("00000000-0000-4000-8000-%012d", i+1)
		if err := SavePeerKeyPin(store, testOwnerA, ids[i], testPin(fingerprintOfLen('a'), PeerKeyPinStateTOFU)); err != nil {
			t.Fatalf("SavePeerKeyPin %d: %v", i, err)
		}
	}

	chunk0 := readChunk(t, store, testOwnerA, 0)
	if len(chunk0.Peers) != PeerKeyPinIndexChunkSize {
		t.Fatalf("chunk 0 holds %d ids, want %d", len(chunk0.Peers), PeerKeyPinIndexChunkSize)
	}
	chunk1 := readChunk(t, store, testOwnerA, 1)
	if len(chunk1.Peers) != 1 || chunk1.Peers[0] != ids[PeerKeyPinIndexChunkSize] {
		t.Fatalf("chunk 1 = %+v, want the one id past the boundary", chunk1.Peers)
	}
	if _, err := store.Get(config.Service, PeerKeyPinIndexAccount(testOwnerA, 2)); !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("chunk 2 exists; enumeration would not stop where it should")
	}

	entries, err := ListPeerKeyPins(store, testOwnerA)
	if err != nil {
		t.Fatalf("ListPeerKeyPins: %v", err)
	}
	if len(entries) != PeerKeyPinIndexChunkSize+1 {
		t.Fatalf("listed %d pins across chunks, want %d", len(entries), PeerKeyPinIndexChunkSize+1)
	}

	// Emptying chunk 0 must leave it in place, or chunk 1 becomes unreachable.
	for _, id := range ids[:PeerKeyPinIndexChunkSize] {
		if _, err := DeletePeerKeyPin(store, testOwnerA, id); err != nil {
			t.Fatalf("DeletePeerKeyPin %s: %v", id, err)
		}
	}
	chunk0 = readChunk(t, store, testOwnerA, 0)
	if len(chunk0.Peers) != 0 {
		t.Fatalf("chunk 0 still holds %d ids after deleting them all", len(chunk0.Peers))
	}
	entries, err = ListPeerKeyPins(store, testOwnerA)
	if err != nil {
		t.Fatalf("ListPeerKeyPins after deletes: %v", err)
	}
	if len(entries) != 1 || entries[0].AccountID != ids[PeerKeyPinIndexChunkSize] {
		t.Fatalf("listed %+v, want only the id in chunk 1", entries)
	}
}

// Windows Credential Manager allows roughly 2.5 KB per entry. Both record
// shapes must sit under PeerKeyPinMaxItemBytes at their worst case.
func TestPeerKeyPin_SizeBounds(t *testing.T) {
	store := NewMemorySecretStore()

	worst := PeerKeyPin{
		V:                       PeerKeyPinVersion,
		Fingerprint:             fingerprintOfLen('a'),
		State:                   PeerKeyPinStateVerified,
		FirstSeenAt:             9007199254740991,
		LastSeenAt:              9007199254740991,
		VerifiedAt:              9007199254740991,
		LastRotationFingerprint: fingerprintOfLen('b'),
	}
	encoded, err := json.Marshal(worst)
	if err != nil {
		t.Fatalf("marshal pin: %v", err)
	}
	if len(encoded) >= PeerKeyPinMaxItemBytes {
		t.Fatalf("pin record is %d bytes, want under %d", len(encoded), PeerKeyPinMaxItemBytes)
	}

	for i := 0; i < PeerKeyPinIndexChunkSize; i++ {
		id := fmt.Sprintf("ffffffff-ffff-4fff-8fff-%012d", i+1)
		if err := SavePeerKeyPin(store, testOwnerA, id, worst); err != nil {
			t.Fatalf("SavePeerKeyPin %d: %v", i, err)
		}
	}
	raw, err := store.Get(config.Service, PeerKeyPinIndexAccount(testOwnerA, 0))
	if err != nil {
		t.Fatalf("read full index chunk: %v", err)
	}
	if len(raw) >= PeerKeyPinMaxItemBytes {
		t.Fatalf("full index chunk is %d bytes, want under %d", len(raw), PeerKeyPinMaxItemBytes)
	}
	chunk := readChunk(t, store, testOwnerA, 0)
	if len(chunk.Peers) != PeerKeyPinIndexChunkSize {
		t.Fatalf("full chunk holds %d ids, want %d", len(chunk.Peers), PeerKeyPinIndexChunkSize)
	}
}

// Pins are owner-scoped. Two accounts sharing one device see neither each
// other's fingerprints nor each other's deletes.
func TestPeerKeyPin_OwnerScope(t *testing.T) {
	store := NewMemorySecretStore()

	aPin := testPin(fingerprintOfLen('a'), PeerKeyPinStateVerified)
	aPin.VerifiedAt = 1758243600
	if err := SavePeerKeyPin(store, testOwnerA, testPeer1, aPin); err != nil {
		t.Fatalf("SavePeerKeyPin owner A: %v", err)
	}
	if err := SavePeerKeyPin(store, testOwnerB, testPeer1, testPin(fingerprintOfLen('b'), PeerKeyPinStateTOFU)); err != nil {
		t.Fatalf("SavePeerKeyPin owner B: %v", err)
	}

	gotB, err := GetPeerKeyPin(store, testOwnerB, testPeer1)
	if err != nil {
		t.Fatalf("GetPeerKeyPin owner B: %v", err)
	}
	if gotB.State != PeerKeyPinStateTOFU || gotB.Fingerprint != fingerprintOfLen('b') {
		t.Fatalf("owner B sees %+v, want its own tofu pin", gotB)
	}

	if _, err := DeletePeerKeyPin(store, testOwnerB, testPeer1); err != nil {
		t.Fatalf("DeletePeerKeyPin owner B: %v", err)
	}
	gotA, err := GetPeerKeyPin(store, testOwnerA, testPeer1)
	if err != nil {
		t.Fatalf("GetPeerKeyPin owner A after B's delete: %v", err)
	}
	if gotA.State != PeerKeyPinStateVerified || gotA.VerifiedAt != 1758243600 {
		t.Fatalf("owner A pin = %+v, want its verified pin untouched", gotA)
	}
	entriesA, err := ListPeerKeyPins(store, testOwnerA)
	if err != nil {
		t.Fatalf("ListPeerKeyPins owner A: %v", err)
	}
	if len(entriesA) != 1 {
		t.Fatalf("owner A lists %d pins, want 1", len(entriesA))
	}
	entriesB, err := ListPeerKeyPins(store, testOwnerB)
	if err != nil {
		t.Fatalf("ListPeerKeyPins owner B: %v", err)
	}
	if len(entriesB) != 0 {
		t.Fatalf("owner B lists %d pins after forgetting its only one", len(entriesB))
	}
}

// failingIndexStore fails the index write and nothing else, which is the one
// way a delete can half-succeed.
type failingIndexStore struct {
	SecretStore
	err error
}

func (s failingIndexStore) Set(service, account, value string) error {
	if strings.HasPrefix(account, config.PeerKeyPinIndexPrefix) {
		return s.err
	}
	return s.SecretStore.Set(service, account, value)
}

// The record and the index are two writes and are not atomic. When the second
// one fails the first still happened, so the caller must not be told that
// nothing was forgotten.
func TestPeerKeyPin_DeleteReportsRemovalEvenWhenIndexWriteFails(t *testing.T) {
	inner := NewMemorySecretStore()
	if err := SavePeerKeyPin(inner, testOwnerA, testPeer1, testPin(fingerprintOfLen('a'), PeerKeyPinStateTOFU)); err != nil {
		t.Fatalf("SavePeerKeyPin: %v", err)
	}

	store := failingIndexStore{SecretStore: inner, err: errors.New("keyring is unavailable")}
	forgotten, err := DeletePeerKeyPin(store, testOwnerA, testPeer1)
	if err == nil {
		t.Fatal("expected the index write failure to surface")
	}
	if !forgotten {
		t.Fatal("delete removed the record but reported nothing forgotten")
	}
	if _, err := GetPeerKeyPin(inner, testOwnerA, testPeer1); !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("record still present after the delete: %v", err)
	}

	// The stale index entry repairs itself on the next listing.
	entries, err := ListPeerKeyPins(inner, testOwnerA)
	if err != nil {
		t.Fatalf("ListPeerKeyPins: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("listed %+v, want nothing", entries)
	}
}

func readChunk(t *testing.T, store SecretStore, ownerAccountID string, n int) peerKeyPinIndexChunk {
	t.Helper()
	raw, err := store.Get(config.Service, PeerKeyPinIndexAccount(ownerAccountID, n))
	if err != nil {
		t.Fatalf("read index chunk %d: %v", n, err)
	}
	var chunk peerKeyPinIndexChunk
	if err := json.Unmarshal([]byte(raw), &chunk); err != nil {
		t.Fatalf("decode index chunk %d: %v", n, err)
	}
	if chunk.V != PeerKeyPinVersion {
		t.Fatalf("index chunk %d has v=%d, want %d", n, chunk.V, PeerKeyPinVersion)
	}
	return chunk
}
