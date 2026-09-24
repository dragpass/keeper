package chatstate

import (
	"bytes"
	"errors"
	"testing"
)

// An app that loses its own note of a Commit it built (browser data cleared)
// still has to settle that Commit: the Keeper holds it pending, and until the
// server's log names a winner nothing else can be sent. So the app's
// description of the Commit is kept with it and comes back with the status,
// across a restart.
func TestAPendingCommitKeepsTheAppContextItWasBuiltWith(t *testing.T) {
	store, secrets := newTestStore(t)
	seedGroupState(t, store, testConvA, 4, 2, 7)
	context := []byte(`{"v":1,"flow":"chat"}`)
	if _, err := store.BeginCommit(testConvA, noWatermark, BeginCommitRequest{
		ClientCommitID: testCommitA,
		Plan:           CommitPlan{RemoveAccountIDs: []string{"someone"}, UserInitiated: true},
		AppContext:     context,
	}, &fakeCommitter{}); err != nil {
		t.Fatal(err)
	}
	// A retry answers from the stored Commit and keeps the first context: the
	// bytes it reposts are the first build's, and so is their description.
	if _, err := store.BeginCommit(testConvA, noWatermark, BeginCommitRequest{
		ClientCommitID: testCommitA,
		AppContext:     []byte(`{"v":1,"flow":"other"}`),
	}, &fakeCommitter{}); err != nil {
		t.Fatal(err)
	}
	store.Close()

	reopened, err := Open(secrets, testOwner)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	status, err := reopened.Status(testConvA, noWatermark, &fakeCommitter{})
	if err != nil {
		t.Fatal(err)
	}
	if !status.CommitPending || !bytes.Equal(status.PendingAppContext, context) {
		t.Fatalf("status after reopen = %+v", status)
	}

	if _, err := reopened.ConfirmCommit(testConvA, noWatermark,
		CommitOutcome{ClientCommitID: testCommitA, Kind: CommitAccepted}, &fakeCommitter{}); err != nil {
		t.Fatal(err)
	}
	status, err = reopened.Status(testConvA, noWatermark, &fakeCommitter{})
	if err != nil || status.CommitPending || status.PendingAppContext != nil {
		t.Fatalf("status after the verdict = %+v, %v", status, err)
	}
}

func TestAnOversizedAppContextBuildsNothing(t *testing.T) {
	store, _ := newTestStore(t)
	seedGroupState(t, store, testConvA, 1, 0, 0)
	cipher := &fakeCommitter{}
	_, err := store.BeginCommit(testConvA, noWatermark, BeginCommitRequest{
		ClientCommitID: testCommitA,
		AppContext:     make([]byte, MaxPendingAppContextBytes+1),
	}, cipher)
	if err == nil || errors.Is(err, ErrCommitPending) {
		t.Fatalf("an oversized app context = %v", err)
	}
	if cipher.builds != 0 {
		t.Fatal("a Commit was built for a request that was refused")
	}
}

// A room Commit's name is sealed for the epoch the Commit creates, from the
// pending Commit, and an app that lost the build's answer has no plaintext
// name to seal it again from. The first seal is kept with the Commit and
// reported with the status; it opens once the Commit is the epoch's. A retry
// without a name still answers with none, which is what an app asking for
// none expects.
func TestAPendingCommitReportsTheNameItsFirstBuildSealed(t *testing.T) {
	store, _ := newTestStore(t)
	seedGroupState(t, store, testConvA, 1, 0, 0)
	built, err := store.BeginCommit(testConvA, noWatermark, BeginCommitRequest{
		ClientCommitID: testCommitA, RoomName: []byte("renamed"),
	}, &fakeCommitter{})
	if err != nil || built.RoomName == nil {
		t.Fatalf("begin commit = %+v, %v", built, err)
	}
	retry, err := store.BeginCommit(testConvA, noWatermark, BeginCommitRequest{
		ClientCommitID: testCommitA,
	}, &fakeCommitter{})
	if err != nil || retry.Created || retry.RoomName != nil {
		t.Fatalf("retry without a name = %+v, %v", retry, err)
	}
	status, err := store.Status(testConvA, noWatermark, &fakeCommitter{})
	if err != nil {
		t.Fatal(err)
	}
	got := status.PendingName
	if got == nil || got.Epoch != 2 || !bytes.Equal(got.IV, built.RoomName.IV) ||
		!bytes.Equal(got.Ciphertext, built.RoomName.Ciphertext) {
		t.Fatalf("pending name = %+v; the first build sealed %+v", got, built.RoomName)
	}
	if _, err := store.ConfirmCommit(testConvA, noWatermark,
		CommitOutcome{ClientCommitID: testCommitA, Kind: CommitAccepted}, &fakeCommitter{}); err != nil {
		t.Fatal(err)
	}
	if name, err := openNameForTest(store, testConvA, *got); err != nil || name != "renamed" {
		t.Fatalf("open after the verdict = %q, %v", name, err)
	}
	if status, err = store.Status(testConvA, noWatermark, &fakeCommitter{}); err != nil || status.PendingName != nil {
		t.Fatalf("status after the verdict = %+v, %v", status, err)
	}
}
