//go:build mls && cgo

// A message from a prior epoch whose sending leaf has since left the group.
// mls-rs keeps no credentials for a prior epoch, so once the leaf is blank or
// held by someone else it refuses the message rather than name it after the
// leaf's new holder. The display batch answers that one message as
// sender_unavailable; it used to refuse the whole batch, and a page that
// held one such message never opened again.
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

	room := priorEpochRoom{g: g, carolS: carolS, carolStore: carolStore}
	for range 2 {
		sent, err := sendAs(bobStore, bobS, noWatermark)
		if err != nil {
			t.Fatalf("bob sends: %v", err)
		}
		room.fromBob = append(room.fromBob, sent)
	}
	return room
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

// Alice removes bob with her own Commit, and carol applies it from the log,
// both before opening what bob sent. That message does not open for either,
// and the rest of the batch still does.
func TestAMessageFromARemovedSenderDoesNotRefuseTheBatch(t *testing.T) {
	room := newPriorEpochRoom(t)
	removal := room.g.beginRemove(t, noWatermark, accountB)
	room.g.confirm(t, removal.ClientCommitID)
	if _, err := room.carolStore.Receive(conv, noWatermark, chatstate.ReceiveRequest{
		Seq: 10, Message: removal.Commit,
	}, mls.NewCipher(room.carolS, trustAll{})); err != nil {
		t.Fatalf("carol applies the remove: %v", err)
	}
	fromCarol, err := sendAs(room.carolStore, room.carolS, noWatermark)
	if err != nil {
		t.Fatalf("carol sends after the remove: %v", err)
	}

	got := openBatch(t, room.g.aliceStore, room.g.aliceS,
		request(5, room.fromBob[0]), request(11, fromCarol))
	wantSenderUnavailable(t, got[0])
	if got[1].Sender.AccountID != accountC || string(got[1].Plaintext) == "" {
		t.Fatalf("carol's message after the remove = %+v; want it shown as hers", got[1])
	}

	wantSenderUnavailable(t, openBatch(t, room.carolStore, room.carolS, request(5, room.fromBob[0]))[0])

	// Nothing was written for it: asking again answers the same.
	wantSenderUnavailable(t, openBatch(t, room.g.aliceStore, room.g.aliceS, request(5, room.fromBob[0]))[0])
}

// Bob's leaf goes blank and the next Add fills it. His earlier message is not
// shown under the newcomer's name.
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

	wantSenderUnavailable(t, openBatch(t, room.g.aliceStore, room.g.aliceS, request(6, room.fromBob[1]))[0])
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
