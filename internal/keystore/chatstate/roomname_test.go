package chatstate

import (
	"errors"
	"testing"
)

func openNameForTest(store *Store, conv string, sealed SealedRoomName) (string, error) {
	name, err := store.OpenRoomName(conv, noWatermark, sealed.Epoch, sealed.IV, sealed.Ciphertext, &fakeCommitter{})
	return string(name), err
}

func TestARoomNameOpensOnlyForTheConfirmedEpoch(t *testing.T) {
	store, _ := newTestStore(t)
	seedGroupState(t, store, testConvA, 3, 0, 0)
	before := readRecordForTest(t, store, testConvA).Generation

	sealed, err := store.SealRoomName(testConvA, noWatermark, []byte("팀 방"), &fakeCommitter{})
	if err != nil || sealed.Epoch != 3 || len(sealed.IV) != ivBytes {
		t.Fatalf("seal = %+v, %v", sealed, err)
	}
	if name, err := openNameForTest(store, testConvA, sealed); err != nil || name != "팀 방" {
		t.Fatalf("open = %q, %v", name, err)
	}

	stale := sealed
	stale.Epoch = 2
	if _, err := openNameForTest(store, testConvA, stale); !errors.Is(err, ErrEpochStale) {
		t.Fatalf("open for another epoch = %v", err)
	}
	tampered := sealed
	tampered.Ciphertext = append([]byte(nil), sealed.Ciphertext...)
	tampered.Ciphertext[0] ^= 1
	if _, err := openNameForTest(store, testConvA, tampered); !errors.Is(err, ErrRoomNameUnopenable) {
		t.Fatalf("open of an altered name = %v", err)
	}
	// Another conversation's group at the same epoch has another key and AAD.
	seedGroupState(t, store, testConvB, 3, 0, 0)
	if _, err := openNameForTest(store, testConvB, sealed); !errors.Is(err, ErrRoomNameUnopenable) {
		t.Fatalf("open under another conversation = %v", err)
	}
	for _, bad := range [][]byte{nil, {}, make([]byte, MaxRoomNameBytes+1)} {
		if _, err := store.SealRoomName(testConvA, noWatermark, bad, &fakeCommitter{}); err == nil {
			t.Fatalf("a %d-byte name was sealed", len(bad))
		}
	}
	if got := readRecordForTest(t, store, testConvA).Generation; got != before {
		t.Fatal("sealing or opening a name wrote the record")
	}
	if _, err := store.SealRoomName("99999999-9999-4999-8999-999999999999", noWatermark, []byte("x"), &fakeCommitter{}); !errors.Is(err, ErrNoGroupState) {
		t.Fatalf("seal without a group = %v", err)
	}
}

// A Commit carries the name into the epoch it creates, before the CAS. Once
// the Commit is confirmed that name opens and the old epoch's does not.
func TestACommitResealsTheNameForTheEpochItCreates(t *testing.T) {
	store, _ := newTestStore(t)
	seedGroupState(t, store, testConvA, 1, 0, 0)
	old, err := store.SealRoomName(testConvA, noWatermark, []byte("before"), &fakeCommitter{})
	if err != nil {
		t.Fatal(err)
	}

	built, err := store.BeginCommit(testConvA, noWatermark, BeginCommitRequest{
		ClientCommitID: testCommitA, RoomName: []byte("renamed"),
	}, &fakeCommitter{})
	if err != nil || built.RoomName == nil || built.RoomName.Epoch != 2 {
		t.Fatalf("begin commit = %+v, %v", built, err)
	}
	// Still epoch 1 until the verdict: the new name does not open yet.
	if _, err := openNameForTest(store, testConvA, *built.RoomName); !errors.Is(err, ErrEpochStale) {
		t.Fatalf("open of the next epoch's name before the verdict = %v", err)
	}

	retry, err := store.BeginCommit(testConvA, noWatermark, BeginCommitRequest{
		ClientCommitID: testCommitA, RoomName: []byte("renamed"),
	}, &fakeCommitter{})
	if err != nil || retry.Created || retry.RoomName == nil || retry.RoomName.Epoch != 2 {
		t.Fatalf("retried begin commit = %+v, %v", retry, err)
	}

	if _, err := store.ConfirmCommit(testConvA, noWatermark,
		CommitOutcome{ClientCommitID: testCommitA, Kind: CommitAccepted}, &fakeCommitter{}); err != nil {
		t.Fatal(err)
	}
	for _, sealed := range []SealedRoomName{*built.RoomName, *retry.RoomName} {
		if name, err := openNameForTest(store, testConvA, sealed); err != nil || name != "renamed" {
			t.Fatalf("open after the verdict = %q, %v", name, err)
		}
	}
	if _, err := openNameForTest(store, testConvA, old); !errors.Is(err, ErrEpochStale) {
		t.Fatalf("open of the old epoch's name = %v", err)
	}
}

func TestACreateSealsTheNameForEpochOne(t *testing.T) {
	store, _ := newTestStore(t)
	built, err := store.CreateGroup(testConvA, noWatermark, BeginCommitRequest{
		ClientCommitID: testCommitA,
		Plan:           CommitPlan{AddKeyPackages: [][]byte{[]byte("a key package")}, UserInitiated: true},
		RoomName:       []byte("room"),
	}, &fakeCreator{})
	if err != nil || built.RoomName == nil || built.RoomName.Epoch != 1 {
		t.Fatalf("create = %+v, %v", built, err)
	}
	// The epoch 0 name the server stores at room creation is sealed while the
	// create is pending.
	zero, err := store.SealRoomName(testConvA, noWatermark, []byte("room"), &fakeCommitter{})
	if err != nil || zero.Epoch != 0 {
		t.Fatalf("epoch 0 seal = %+v, %v", zero, err)
	}
}

// A name that cannot be resealed refuses the build and persists no Commit.
func TestAFailedResealPersistsNoCommit(t *testing.T) {
	store, _ := newTestStore(t)
	seedGroupState(t, store, testConvA, 1, 0, 0)
	before := readRecordForTest(t, store, testConvA)
	refuse := errors.New("no exporter")
	if _, err := store.BeginCommit(testConvA, noWatermark, BeginCommitRequest{
		ClientCommitID: testCommitA, RoomName: []byte("x"),
	}, &fakeCommitter{exportErr: refuse}); !errors.Is(err, refuse) {
		t.Fatalf("begin commit with a failing reseal = %v", err)
	}
	if _, err := store.BeginCommit(testConvA, noWatermark, BeginCommitRequest{
		ClientCommitID: testCommitA, RoomName: make([]byte, MaxRoomNameBytes+1),
	}, &fakeCommitter{}); err == nil {
		t.Fatal("an oversized name was resealed")
	}
	after := readRecordForTest(t, store, testConvA)
	if after.Generation != before.Generation || after.Pending != nil {
		t.Fatal("a refused reseal left a pending commit")
	}
	if _, err := store.CreateGroup(testConvB, noWatermark, BeginCommitRequest{
		ClientCommitID: testCommitA,
		Plan:           CommitPlan{AddKeyPackages: [][]byte{[]byte("a key package")}, UserInitiated: true},
		RoomName:       []byte("x"),
	}, &fakeCreator{fakeCommitter{exportErr: refuse}}); !errors.Is(err, refuse) {
		t.Fatalf("create with a failing reseal = %v", err)
	}
	if rec, err := store.readRecord(store.paths(testConvB), testConvB); err != nil || (rec != nil && len(rec.GroupState) != 0) {
		t.Fatalf("a refused create left a group: %+v, %v", rec, err)
	}
}
