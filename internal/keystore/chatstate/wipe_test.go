package chatstate

import (
	"bytes"
	"errors"
	"testing"
)

func allZero(b []byte) bool { return len(b) > 0 && bytes.Count(b, []byte{0}) == len(b) }

// stateCapture is fakeCipher that remembers the state buffer it handed out.
type stateCapture struct {
	fakeCipher
	out []byte
}

type stateCaptureCreator struct {
	fakeCreator
	out []byte
}

func (c *stateCaptureCreator) State() ([]byte, error) {
	state, err := c.fakeCreator.State()
	c.out = state
	return state, err
}

func (c *stateCapture) State() ([]byte, error) {
	state, err := c.fakeCipher.State()
	c.out = state
	return state, err
}

func TestAGroupStateIsWipedWhenCreateFailsAfterSerialization(t *testing.T) {
	store, _ := newTestStore(t)
	cipher := &stateCaptureCreator{fakeCreator: fakeCreator{
		fakeCommitter: fakeCommitter{exportErr: errors.New("room name seal failed")},
	}}
	_, err := store.CreateGroup(testConvA, noWatermark, BeginCommitRequest{
		ClientCommitID: testCommitA,
		Plan:           CommitPlan{AddKeyPackages: [][]byte{[]byte("a key package")}, UserInitiated: true},
		RoomName:       []byte("room"),
	}, cipher)
	if err == nil {
		t.Fatal("create succeeded despite room name seal failure")
	}
	if !allZero(cipher.out) {
		t.Fatal("uncommitted serialized group state survived the failed operation")
	}
	if rec, err := store.readRecord(store.paths(testConvA), testConvA); err != nil || rec != nil {
		t.Fatalf("failed create persisted a record: %+v, %v", rec, err)
	}
}

func TestAGroupStateIsWipedWhenBeginCommitFailsAfterSerialization(t *testing.T) {
	store, _ := newTestStore(t)
	seedGroupState(t, store, testConvA, 1, 0, 0)
	cipher := &stateCaptureCreator{fakeCreator: fakeCreator{fakeCommitter: fakeCommitter{
		exportErr: errors.New("room name seal failed"),
	}}}
	_, err := store.BeginCommit(testConvA, noWatermark, BeginCommitRequest{
		ClientCommitID: testCommitA,
		Plan:           CommitPlan{AddKeyPackages: [][]byte{[]byte("a key package")}, UserInitiated: true},
		RoomName:       []byte("room"),
	}, cipher)
	if err == nil {
		t.Fatal("begin commit succeeded despite room name seal failure")
	}
	if !allZero(cipher.out) {
		t.Fatal("uncommitted serialized group state survived the failed operation")
	}
	if rec := readRecordForTest(t, store, testConvA); rec.Pending != nil || allZero(rec.GroupState) {
		t.Fatalf("failed commit changed the record: pending=%+v, state zero=%v", rec.Pending, allZero(rec.GroupState))
	}
}

// A locked cycle wipes the group state it held once it ends: the copy it read
// from the file and the one the MLS layer handed it to write. Only the file
// keeps the state, and what LoadGroupState hands out is the caller's own copy.
func TestALockedCycleWipesTheGroupStateItHeld(t *testing.T) {
	store, _ := newTestStore(t)
	given := fakeState(0, 2, 0)
	if _, err := store.SaveGroupState(testConvA, noWatermark, given); err != nil {
		t.Fatal(err)
	}
	if allZero(given) {
		t.Fatal("SaveGroupState wiped the caller's buffer")
	}

	var held []byte
	if err := store.withConversation(testConvA, func(p convPaths) error {
		rec, _, err := store.loadChecked(p, testConvA, noWatermark)
		if err == nil {
			held = rec.GroupState
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if !allZero(held) {
		t.Fatal("the group state read inside the cycle survived it")
	}

	cipher := &stateCapture{}
	if _, err := store.Send(testConvA, noWatermark, SendRequest{
		ClientMessageID: testClientA, Plaintext: []byte("hello"),
	}, cipher); err != nil {
		t.Fatal(err)
	}
	if !allZero(cipher.out) {
		t.Fatal("the group state the send wrote survived the cycle")
	}
	if rec := readRecordForTest(t, store, testConvA); len(rec.GroupState) == 0 || allZero(rec.GroupState) {
		t.Fatal("the wipe reached the file")
	}

	loaded, err := store.LoadGroupState(testConvA, noWatermark)
	if err != nil || len(loaded) == 0 || allZero(loaded) {
		t.Fatalf("LoadGroupState handed out a wiped buffer: %v", err)
	}
}
