//go:build mls && cgo

// S-1 through real MLS (design §6.4.1): a permit naming a removed account
// latches encryption, and only this device's own confirmed roster — never a
// pending Commit, never a later permit — releases it. The roster is the
// library's, which is why these run against mls-rs rather than a stand-in.
package mls_test

import (
	"bytes"
	"errors"
	"strconv"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/chatstate"
	"github.com/dragpass/keeper/internal/keystore/mls"
)

func removalOf(accounts ...string) chatstate.ServerWatermark {
	return chatstate.ServerWatermark{PendingRemovals: accounts}
}

var sendSeq int

func sendAs(store *chatstate.Store, s *mls.Session, wm chatstate.ServerWatermark) (chatstate.SendResult, error) {
	sendSeq++
	return store.Send(conv, wm, chatstate.SendRequest{
		ClientMessageID: "44444444-4444-4444-8444-" + strconv.FormatInt(int64(400000000000+sendSeq), 10),
		Plaintext:       []byte("안건 정리해서 올려 주세요"),
	}, mls.NewCipher(s, trustAll{}))
}

func (g groupOf) mustSend(t testing.TB, wm chatstate.ServerWatermark) chatstate.SendResult {
	t.Helper()
	out, err := sendAs(g.aliceStore, g.aliceS, wm)
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	return out
}

func (g groupOf) refusedSend(t testing.TB, wm chatstate.ServerWatermark, why string) {
	t.Helper()
	if _, err := sendAs(g.aliceStore, g.aliceS, wm); !errors.Is(err, chatstate.ErrRotationPending) {
		t.Fatalf("%s: send = %v; want ErrRotationPending", why, err)
	}
}

// beginRemove is a Remove a person on alice's device asked for. These groups
// carry no roles (legacy_temporary), so that is what lets alice build it; the
// authority rules have their own tests, and these are about the latch.
func (g groupOf) beginRemove(t testing.TB, wm chatstate.ServerWatermark, accounts ...string) chatstate.BeginCommitResult {
	t.Helper()
	out, err := g.aliceStore.BeginCommit(conv, wm, chatstate.BeginCommitRequest{
		ClientCommitID: nextCommitID(),
		Plan:           chatstate.CommitPlan{RemoveAccountIDs: accounts, UserInitiated: true},
	}, mls.NewCipher(g.aliceS, trustAll{}))
	if err != nil {
		t.Fatalf("a remove commit was refused while latched: %v", err)
	}
	return out
}

func (g groupOf) loseTo(t testing.TB, id string, winner []byte, wm chatstate.ServerWatermark) {
	t.Helper()
	cipher := mls.NewCipher(g.aliceS, trustAll{})
	cipher.SetEvidence(everyRemoval{})
	if _, err := g.aliceStore.ConfirmCommit(conv, wm, chatstate.CommitOutcome{
		ClientCommitID: id, Kind: chatstate.CommitSuperseded, WinnerMessage: winner,
	}, cipher); err != nil {
		t.Fatalf("settle a lost race: %v", err)
	}
}

// everyRemoval stands in for a verified statement behind every Remove, so a
// winner's Remove is applied and the latch is what is under test.
type everyRemoval struct{}

func (everyRemoval) Authorized(change chatstate.CommitChange) ([]bool, int, error) {
	out := make([]bool, len(change.Removed))
	for i := range out {
		out[i] = true
	}
	return out, 0, nil
}

// threeMembers is alice, bob and carol, with alice and carol on the same
// confirmed epoch so either can win the next one.
func threeMembers(t *testing.T) (g groupOf, carolS *mls.Session, carolStore *chatstate.Store) {
	t.Helper()
	g = newGroup(t)
	g.memberOf(t, newAccount(t, accountB), device1)
	carolS, carolStore = g.memberOf(t, newAccount(t, accountC), device1)
	return g, carolS, carolStore
}

// carolCommits builds carol's attempt at the epoch alice is also on, under
// carol's own permit. Only its bytes matter: in the race alice loses, it is
// the Commit the server kept.
func carolCommits(
	t testing.TB, s *mls.Session, store *chatstate.Store, wm chatstate.ServerWatermark, plan chatstate.CommitPlan,
) []byte {
	t.Helper()
	out, err := store.BeginCommit(conv, wm, chatstate.BeginCommitRequest{
		ClientCommitID: nextCommitID(), Plan: plan,
	}, mls.NewCipher(s, trustAll{}))
	if err != nil {
		t.Fatal(err)
	}
	return out.Commit
}

// A permit naming a member latches the conversation, and the refused send
// consumes nothing: the stored state is byte-identical and the next generation
// is still the one the refused send would have taken.
func TestS1_ANamedMemberLatchesAndARefusedSendTakesNoPosition(t *testing.T) {
	g := newGroup(t)
	g.memberOf(t, newAccount(t, accountB), device1)
	first := g.mustSend(t, noWatermark)

	before := g.storedState(t)
	g.refusedSend(t, removalOf(accountB), "a permit named bob")
	if !bytes.Equal(before, g.storedState(t)) {
		t.Fatal("a refused send changed the stored group state")
	}
	if _, err := mls.Restore(g.aliceStore, conv, noWatermark, g.aliceS); err != nil {
		t.Fatal(err)
	}
	epoch, _, generation, err := g.aliceS.SendPosition()
	if err != nil {
		t.Fatal(err)
	}
	if epoch != first.Entry.Position.Epoch || uint64(generation) != first.Entry.Position.Generation+1 {
		t.Fatalf("send position moved to (%d, %d) after a refusal; want (%d, %d)",
			epoch, generation, first.Entry.Position.Epoch, first.Entry.Position.Generation+1)
	}
}

// The server leaving bob out of the next permits is not evidence that his leaf
// is gone (§6.4.1 condition 3). A process restart does not forget it either.
func TestS1_ThePermitDroppingTheAccountDoesNotUnlatch(t *testing.T) {
	g := newGroup(t)
	g.memberOf(t, newAccount(t, accountB), device1)
	g.refusedSend(t, removalOf(accountB), "a permit named bob")

	g.refusedSend(t, noWatermark, "the next permit left bob out")
	g.refusedSend(t, removalOf(accountM), "the next permit named somebody else")

	restarted := groupOf{
		alice:      g.alice,
		aliceStore: openStore(t, g.alice.store, g.alice.id),
		aliceS:     g.alice.session(t),
	}
	restarted.refusedSend(t, noWatermark, "after a restart")
}

// A built Remove is a fork until the server takes it: nothing is unlatched by
// building it, and the Commit itself is never what the latch refuses. Once it
// is confirmed the leaf is gone from the confirmed tree and sending resumes,
// even under a permit that still names bob.
func TestS1_OnlyTheConfirmedRemoveUnlatches(t *testing.T) {
	g := newGroup(t)
	g.memberOf(t, newAccount(t, accountB), device1)
	g.refusedSend(t, removalOf(accountB), "a permit named bob")

	pending := g.beginRemove(t, removalOf(accountB), accountB)
	if _, err := sendAs(g.aliceStore, g.aliceS, noWatermark); !errors.Is(err, chatstate.ErrCommitPending) {
		t.Fatalf("send with a remove pending = %v; want ErrCommitPending", err)
	}
	if _, err := mls.Restore(g.aliceStore, conv, noWatermark, g.aliceS); err != nil {
		t.Fatal(err)
	}
	if accounts, err := mls.NewCipher(g.aliceS, trustAll{}).ConfirmedAccounts(); err != nil ||
		len(accounts) != 2 {
		t.Fatalf("the confirmed roster with a remove pending = %v, %v; want alice and bob", accounts, err)
	}

	g.confirm(t, pending.ClientCommitID)
	g.mustSend(t, removalOf(accountB))
	g.mustSend(t, noWatermark)
}

// Losing the CAS to somebody else's Remove of the same account unlatches: the
// winner's Commit is the confirmed state now, and it holds no leaf of bob.
func TestS1_LosingToAWinnerThatAlsoRemovesUnlatches(t *testing.T) {
	g, carolS, carolStore := threeMembers(t)
	g.refusedSend(t, removalOf(accountB), "a permit named bob")

	winner := carolCommits(t, carolS, carolStore, removalOf(accountB),
		chatstate.CommitPlan{RemoveAccountIDs: []string{accountB}, UserInitiated: true})
	pending := g.beginRemove(t, removalOf(accountB), accountB)
	g.loseTo(t, pending.ClientCommitID, winner, removalOf(accountB))

	g.mustSend(t, removalOf(accountB))
}

// Losing the CAS to a Commit that does not remove bob leaves him latched. The
// race being over is not the removal having happened (condition 4).
func TestS1_LosingToAWinnerThatDoesNotRemoveStaysLatched(t *testing.T) {
	g, carolS, carolStore := threeMembers(t)
	g.refusedSend(t, removalOf(accountB), "a permit named bob")

	winner := carolCommits(t, carolS, carolStore, noWatermark, chatstate.CommitPlan{})
	pending := g.beginRemove(t, removalOf(accountB), accountB)
	g.loseTo(t, pending.ClientCommitID, winner, noWatermark)

	g.refusedSend(t, noWatermark, "the winner kept bob's leaf")

	// And the way out is still open: a fresh Remove on the new epoch.
	g.confirm(t, g.beginRemove(t, noWatermark, accountB).ClientCommitID)
	g.mustSend(t, noWatermark)
}

// An account the confirmed roster does not hold has no leaf to protect
// against, so naming it latches nothing now and nothing later.
func TestS1_AnAccountOutsideTheRosterIsNotLatched(t *testing.T) {
	g := newGroup(t)
	g.memberOf(t, newAccount(t, accountB), device1)

	g.mustSend(t, removalOf(accountM))
	g.mustSend(t, noWatermark)
}

// Receiving stays open while latched, and applying a message does not unlatch.
func TestS1_ReceivingStaysOpenWhileLatched(t *testing.T) {
	g := newGroup(t)
	bobS, bobStore := g.memberOf(t, newAccount(t, accountB), device1)
	g.refusedSend(t, removalOf(accountB), "a permit named bob")

	sent, err := sendAs(bobStore, bobS, noWatermark)
	if err != nil {
		t.Fatal(err)
	}
	got, err := g.aliceStore.Receive(conv, removalOf(accountB),
		chatstate.ReceiveRequest{Seq: 1, Message: sent.Entry.Ciphertext}, mls.NewCipher(g.aliceS, trustAll{}))
	if err != nil {
		t.Fatalf("receive while latched: %v", err)
	}
	if len(got.Plaintext) == 0 {
		t.Fatal("receive while latched returned no plaintext")
	}
	g.refusedSend(t, noWatermark, "after receiving")
}

// A Remove of an account with no leaf is refused rather than built as a
// Commit that removes nobody, which would read as the removal having happened.
func TestS1_ARemoveOfAnAccountWithNoLeafBuildsNothing(t *testing.T) {
	g := newGroup(t)
	g.memberOf(t, newAccount(t, accountB), device1)
	if _, err := g.aliceStore.BeginCommit(conv, noWatermark, chatstate.BeginCommitRequest{
		ClientCommitID: nextCommitID(),
		Plan:           chatstate.CommitPlan{RemoveAccountIDs: []string{accountM}},
	}, mls.NewCipher(g.aliceS, trustAll{})); err == nil {
		t.Fatal("a remove of an account outside the group was built")
	}
	if _, ok, err := g.aliceStore.PendingCommit(conv, noWatermark); err != nil || ok {
		t.Fatalf("a refused remove left a pending commit (%v, %v)", ok, err)
	}
}
