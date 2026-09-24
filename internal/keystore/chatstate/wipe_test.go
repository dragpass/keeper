package chatstate

import (
	"bytes"
	"testing"
)

func allZero(b []byte) bool { return len(b) > 0 && bytes.Count(b, []byte{0}) == len(b) }

// stateCapture is fakeCipher that remembers the state buffer it handed out.
type stateCapture struct {
	fakeCipher
	out []byte
}

func (c *stateCapture) State() ([]byte, error) {
	state, err := c.fakeCipher.State()
	c.out = state
	return state, err
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
