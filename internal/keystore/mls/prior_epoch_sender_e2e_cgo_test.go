//go:build mls && cgo

// A message from a prior epoch whose sending leaf has since left the group.
// mls-rs keeps only signature public keys for a prior epoch, so once the leaf
// is blank or held by someone else it refuses the message rather than name it
// after the leaf's new holder. The Keeper archives the whole group state of
// every epoch a Commit ends, and opens such a message against the group as it
// stood in its own epoch: the sender is named from that epoch's tree. Without
// the epoch's secrets, or for a message numbered after the Commit that ended
// its epoch, it stays a message that does not open, and the rest of the batch
// still does.
package mls_test

import (
	"testing"

	"github.com/dragpass/keeper/internal/keystore/chatstate"
	"github.com/dragpass/keeper/internal/keystore/mls"
)

// priorEpochRoom is alice (owner), bob and carol on epoch 2, with two
// messages bob sent there that nobody has opened yet.
type priorEpochRoom struct {
	g          groupOf
	bobS       *mls.Session
	bobStore   *chatstate.Store
	carolS     *mls.Session
	carolStore *chatstate.Store
	fromBob    []chatstate.SendResult
}

func newPriorEpochRoom(t *testing.T) priorEpochRoom {
	t.Helper()
	g := newGroup(t)
	bobS, bobStore := g.memberOf(t, newAccount(t, accountB), device1)

	carol := newAccount(t, accountC)
	carolS := carol.device(t, device1)
	in, err := g.add(trustAll{}, keyPackage(t, carolS))
	if err != nil {
		t.Fatal(err)
	}
	out := g.confirm(t, in.ClientCommitID)
	if err := carolS.JoinVerified(out.Welcome, carol.verifier()); err != nil {
		t.Fatalf("carol joins: %v", err)
	}
	carolStore := openStore(t, carol.store, carol.id)
	if _, err := mls.Persist(carolStore, conv, noWatermark, carolS); err != nil {
		t.Fatal(err)
	}
	if _, err := bobStore.Receive(conv, noWatermark, chatstate.ReceiveRequest{
		Seq: 3, Message: in.Commit,
	}, mls.NewCipher(bobS, trustAll{})); err != nil {
		t.Fatalf("bob applies carol's add: %v", err)
	}

	room := priorEpochRoom{g: g, bobS: bobS, bobStore: bobStore, carolS: carolS, carolStore: carolStore}
	for range 2 {
		sent, err := sendAs(bobStore, bobS, noWatermark)
		if err != nil {
			t.Fatalf("bob sends: %v", err)
		}
		room.fromBob = append(room.fromBob, sent)
	}
	return room
}

// carolAppliesFromTheLog applies the remove the way the handshake sync does,
// which records the Commit's seq. Carol sends once first so that her record
// holds the epoch the Commit is judged against.
func (room priorEpochRoom) carolAppliesFromTheLog(t testing.TB, seq uint64, removal chatstate.BeginCommitResult) {
	t.Helper()
	if _, err := sendAs(room.carolStore, room.carolS, noWatermark); err != nil {
		t.Fatalf("carol sends before the remove: %v", err)
	}
	if _, err := room.carolStore.Receive(conv, noWatermark, chatstate.ReceiveRequest{
		Seq: seq, Message: removal.Commit, Handshake: true, ProducedEpoch: removal.ExpectedEpoch + 1,
	}, mls.NewCipher(room.carolS, trustAll{})); err != nil {
		t.Fatalf("carol applies the remove: %v", err)
	}
}

func request(seq uint64, sent chatstate.SendResult) chatstate.ReceiveRequest {
	epoch := sent.Entry.Position.Epoch
	return chatstate.ReceiveRequest{Seq: seq, Message: sent.Entry.Ciphertext, FramedEpoch: &epoch}
}

func openBatch(
	t testing.TB, store *chatstate.Store, s *mls.Session, reqs ...chatstate.ReceiveRequest,
) []chatstate.ReceiveResult {
	t.Helper()
	got, err := store.ReceiveBatch(conv, noWatermark, reqs, nil, mls.NewCipher(s, trustAll{}))
	if err != nil {
		t.Fatalf("display batch: %v", err)
	}
	return got
}

func wantSenderUnavailable(t testing.TB, got chatstate.ReceiveResult) {
	t.Helper()
	if !got.SenderUnavailable || got.Plaintext != nil || got.Sender != (chatstate.Sender{}) {
		t.Fatalf("result = %+v; want sender_unavailable with no content and no sender", got)
	}
}

func wantFromBob(t testing.TB, got chatstate.ReceiveResult, sent chatstate.SendResult) {
	t.Helper()
	if got.SenderUnavailable || got.Sender.AccountID != accountB || string(got.Plaintext) == "" ||
		got.Position.Epoch != sent.Entry.Position.Epoch ||
		got.Position.Generation != sent.Entry.Position.Generation {
		t.Fatalf("result = %+v; want bob's message at its own epoch %d", got, sent.Entry.Position.Epoch)
	}
}

// Alice removes bob with her own Commit, and carol applies it from the log,
// both before opening what bob sent. Both still open it, under bob's name,
// and the rest of the batch opens too.
func TestARemovedSendersEarlierMessageStillOpens(t *testing.T) {
	room := newPriorEpochRoom(t)
	removal := room.g.beginRemove(t, noWatermark, accountB)
	room.g.confirm(t, removal.ClientCommitID)
	room.carolAppliesFromTheLog(t, 10, removal)
	fromCarol, err := sendAs(room.carolStore, room.carolS, noWatermark)
	if err != nil {
		t.Fatalf("carol sends after the remove: %v", err)
	}

	got := openBatch(t, room.g.aliceStore, room.g.aliceS,
		request(5, room.fromBob[0]), request(11, fromCarol))
	wantFromBob(t, got[0], room.fromBob[0])
	if got[1].Sender.AccountID != accountC || string(got[1].Plaintext) == "" {
		t.Fatalf("carol's message after the remove = %+v; want it shown as hers", got[1])
	}

	wantFromBob(t, openBatch(t, room.carolStore, room.carolS, request(5, room.fromBob[0]))[0], room.fromBob[0])

	// Asking again answers from the sealed copy.
	again := openBatch(t, room.g.aliceStore, room.g.aliceS, request(5, room.fromBob[0]))[0]
	if !again.FromHistory || again.Sender.AccountID != accountB || string(again.Plaintext) != string(got[0].Plaintext) {
		t.Fatalf("re-read = %+v; want the same message from the local copy", again)
	}
}

// Bob's leaf goes blank and the next Add fills it. His earlier message is
// named after him from the tree of its epoch, never after the newcomer.
func TestAReusedLeafDoesNotTakeOverAnEarlierSendersMessage(t *testing.T) {
	room := newPriorEpochRoom(t)
	room.g.confirm(t, room.g.beginRemove(t, noWatermark, accountB).ClientCommitID)
	newcomer := newAccount(t, accountM)
	in, err := room.g.add(trustAll{}, keyPackage(t, newcomer.device(t, device1)))
	if err != nil {
		t.Fatal(err)
	}
	room.g.confirm(t, in.ClientCommitID)
	leaves, err := room.g.aliceS.Roster()
	if err != nil {
		t.Fatal(err)
	}
	if !holds(leaves, room.fromBob[1].Entry.Position.SenderLeafIndex, accountM) {
		t.Fatalf("the newcomer did not take bob's leaf %d: %+v",
			room.fromBob[1].Entry.Position.SenderLeafIndex, leaves)
	}

	wantFromBob(t, openBatch(t, room.g.aliceStore, room.g.aliceS, request(6, room.fromBob[1]))[0], room.fromBob[1])
}

// Bob still holds the keys of the epoch his removal ended, and can encrypt
// in it after the remove. A server takes a message only in the epoch it
// confirms, so one numbered after the Commit that ended its epoch was sent
// once that epoch was over. Carol applied that Commit from the log and knows
// its seq: she refuses it, and still opens what bob sent before.
func TestAMessageNumberedAfterTheRemoveDoesNotOpen(t *testing.T) {
	room := newPriorEpochRoom(t)
	removal := room.g.beginRemove(t, noWatermark, accountB)
	room.g.confirm(t, removal.ClientCommitID)
	room.carolAppliesFromTheLog(t, 10, removal)
	late, err := sendAs(room.bobStore, room.bobS, noWatermark)
	if err != nil {
		t.Fatalf("bob encrypts after his removal: %v", err)
	}
	if late.Entry.Position.Epoch != room.fromBob[0].Entry.Position.Epoch {
		t.Fatalf("bob's late message is at epoch %d; the test needs the epoch his removal ended",
			late.Entry.Position.Epoch)
	}

	got := openBatch(t, room.carolStore, room.carolS, request(5, room.fromBob[0]), request(12, late))
	wantFromBob(t, got[0], room.fromBob[0])
	wantSenderUnavailable(t, got[1])
}

// Past the sixteen prior epochs a Keeper keeps, the epoch's secrets and its
// archive are gone together: bob's message is too old to open, and says so.
func TestWithoutTheEpochSecretsTheMessageStaysUnopened(t *testing.T) {
	room := newPriorEpochRoom(t)
	room.g.confirm(t, room.g.beginRemove(t, noWatermark, accountB).ClientCommitID)
	for range 17 {
		built, err := room.g.aliceStore.BeginCommit(conv, noWatermark,
			chatstate.BeginCommitRequest{ClientCommitID: nextCommitID()}, mls.NewCipher(room.g.aliceS, trustAll{}))
		if err != nil {
			t.Fatalf("update: %v", err)
		}
		room.g.confirm(t, built.ClientCommitID)
	}

	got := openBatch(t, room.g.aliceStore, room.g.aliceS, request(5, room.fromBob[0]))[0]
	if !got.EpochUnavailable || got.Plaintext != nil || got.Sender != (chatstate.Sender{}) {
		t.Fatalf("result = %+v; want epoch_unavailable with no content and no sender", got)
	}
}

// Opened before the remove, the message stays readable afterwards from the
// local copy, under bob's name.
func TestAMessageOpenedBeforeTheRemoveStaysReadable(t *testing.T) {
	room := newPriorEpochRoom(t)
	before := openBatch(t, room.g.aliceStore, room.g.aliceS, request(5, room.fromBob[0]))[0]
	if before.Sender.AccountID != accountB {
		t.Fatalf("before the remove = %+v; want bob's message", before)
	}
	room.g.confirm(t, room.g.beginRemove(t, noWatermark, accountB).ClientCommitID)

	after := openBatch(t, room.g.aliceStore, room.g.aliceS, request(5, room.fromBob[0]))[0]
	if after.SenderUnavailable || after.Sender.AccountID != accountB || string(after.Plaintext) != string(before.Plaintext) {
		t.Fatalf("after the remove = %+v; want the same message from the local copy", after)
	}
}

func holds(leaves []mls.Leaf, index uint32, account string) bool {
	for _, leaf := range leaves {
		if leaf.Index != index {
			continue
		}
		got, _, err := mls.ParseCredentialIdentity(leaf.Identity)
		return err == nil && got == account
	}
	return false
}
