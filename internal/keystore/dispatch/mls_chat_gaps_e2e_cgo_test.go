//go:build mls && cgo

// The gaps the extension's v2 wiring exposed, closed end to end through the
// dispatcher with the real MLS library: a device reading its own sent
// messages, a lost DM create being dropped so the winner's group can be
// joined, and a room name that follows the epoch through every Commit.
//
// Every call below is its own Native Messaging request, so the store and the
// MLS session are opened from disk each time: nothing carries over in memory
// between two calls, which is what a Keeper restart between them would be.

package dispatch

import (
	"encoding/base64"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/proto"
)

func (k *keeper) markSentRequest(id string, seq uint64) proto.MLSMarkSentRequest {
	return proto.MLSMarkSentRequest{
		Permit: k.permit(), OrgID: e2eOrg, ConversationID: e2eConv, ClientMessageID: id, Seq: seq,
	}
}

func (k *keeper) markSent(id string, seq uint64) proto.MLSMarkSentResponseData {
	k.t.Helper()
	return k.must(proto.MLSMarkSent, k.markSentRequest(id, seq)).Data.(proto.MLSMarkSentResponseData)
}

// ────────────────────────────────────────────────────────────────────────
// 1. A device reads its own sent messages.
// ────────────────────────────────────────────────────────────────────────

func TestMLSChatE2E_ADeviceReadsItsOwnSentMessages(t *testing.T) {
	c := newDM(t)
	mine := c.alice.encrypt(messageID(1), 1, "from alice")
	own := proto.MLSDisplayMessage{Seq: c.nextSeq(), CiphertextB64: mine.CiphertextB64}
	theirs := c.send(c.bob, 2, 1, "from bob")

	// Before the seq is bound the copy cannot be found by it. The page is not
	// refused: Alice's own row comes back without plaintext, and Bob's message
	// is delivered beside it.
	got := c.alice.decrypt(own, theirs)
	if got.PlaintextB64[0] != "" || got.Items[0].State != proto.MLSDisplayItemStateOwnWithoutCopy ||
		got.Items[0].SenderAccountID != c.alice.id || got.Items[0].SenderDeviceID != e2eDevice ||
		got.Items[0].FromHistory {
		t.Fatalf("own message before mark sent = %q %+v", got.PlaintextB64[0], got.Items[0])
	}
	assertShown(t, got, 1, "from bob", c.bob, false)
	if got.Items[1].State != proto.MLSDisplayItemStateShown {
		t.Fatalf("a delivered message has state %q", got.Items[1].State)
	}

	if bound := c.alice.markSent(messageID(1), own.Seq); !bound.Bound {
		t.Fatalf("mark sent = %+v", bound)
	}
	if again := c.alice.markSent(messageID(1), own.Seq); again.Bound {
		t.Fatalf("mark sent again = %+v; want nothing written", again)
	}

	shown := c.alice.decrypt(own)
	assertShown(t, shown, 0, "from alice", c.alice, true)
	if it := shown.Items[0]; it.Epoch != mine.Epoch || it.SenderLeafIndex != mine.LeafIndex ||
		it.Generation != mine.Generation || it.State != proto.MLSDisplayItemStateShown {
		t.Fatalf("own message item = %+v; want the position the send declared (%+v)", it, mine)
	}
	// The other member reads it the ordinary way.
	assertShown(t, c.bob.decrypt(own), 0, "from alice", c.alice, false)

	// Still readable after the epoch has moved on.
	update := c.bob.buildUpdate(1)
	c.bob.confirm(update.ClientCommitID, proto.MLSCommitOutcomeAccepted, "")
	c.alice.process(c.nextSeq(), 2, update.CommitB64)
	assertShown(t, c.alice.decrypt(own), 0, "from alice", c.alice, true)

	// Refusals: a seq that carries Bob's message, a second seq for a bound
	// message, and a message with no copy on this device. None writes.
	before := c.alice.status()
	c.alice.refused(proto.MLSMarkSent, c.alice.markSentRequest(messageID(1), theirs.Seq), proto.ChatStateErrorCodeConflict)
	c.alice.refused(proto.MLSMarkSent, c.alice.markSentRequest(messageID(1), own.Seq+100), proto.ChatStateErrorCodeConflict)
	c.alice.refused(proto.MLSMarkSent, c.alice.markSentRequest(messageID(9), own.Seq+101), proto.ChatStateErrorCodeNotFound)
	assertShown(t, c.alice.decrypt(theirs), 0, "from bob", c.bob, true)
	if after := c.alice.status(); after.Epoch != before.Epoch {
		t.Fatalf("status moved across refused mark sents: %+v -> %+v", before, after)
	}
}

// A damaged message is still a refusal of the whole page even beside an own
// message without a copy: the exception covers that one outcome only.
func TestMLSChatE2E_AnOwnMessageDoesNotExcuseADamagedOne(t *testing.T) {
	c := newDM(t)
	own := proto.MLSDisplayMessage{Seq: c.nextSeq(), CiphertextB64: c.alice.encrypt(messageID(1), 1, "mine").CiphertextB64}
	bad := c.send(c.bob, 2, 1, "damaged")
	ct, _ := base64.StdEncoding.DecodeString(bad.CiphertextB64)
	ct[len(ct)-1] ^= 1
	bad.CiphertextB64 = base64.StdEncoding.EncodeToString(ct)
	good := c.send(c.bob, 3, 1, "fine")

	resp := c.alice.call(proto.MLSDecryptBatchForAppDisplay, c.alice.decryptRequest(own, bad, good))
	if resp.Success || string(resp.ErrorCode) != proto.ChatMLSErrorCodeFailed || resp.Data != nil {
		t.Fatalf("a page with a damaged message = %+v", resp)
	}
	// Nothing was written: Bob's good message is still a first delivery.
	assertShown(t, c.alice.decrypt(good), 0, "fine", c.bob, false)
}

// ────────────────────────────────────────────────────────────────────────
// 2. A lost DM create is discarded and the winner's group joined.
// ────────────────────────────────────────────────────────────────────────

func (k *keeper) discardRequest(id string) proto.MLSGroupDiscardUnacceptedRequest {
	return proto.MLSGroupDiscardUnacceptedRequest{
		Permit: k.permit(), OrgID: e2eOrg, ConversationID: e2eConv, ClientCommitID: id,
	}
}

func (k *keeper) discard(id string) proto.MLSGroupDiscardUnacceptedResponseData {
	k.t.Helper()
	return k.must(proto.MLSGroupDiscardUnaccepted, k.discardRequest(id)).Data.(proto.MLSGroupDiscardUnacceptedResponseData)
}

func TestMLSChatE2E_ALostDMCreateIsDiscardedAndTheWinnerJoined(t *testing.T) {
	e2eStateRoot(t)
	alice, bob := newKeeper(t, e2eAlice), newKeeper(t, e2eBob)

	// Both open the DM at the same moment. Each builds a create under the one
	// conversation id; the server takes Alice's.
	aliceID, bobID := alice.nextCommitID(), bob.nextCommitID()
	aliceCreate := commitOf(alice.must(proto.MLSGroupCreate, proto.MLSGroupCreateRequest{
		Permit: alice.permit(), OrgID: e2eOrg, ConversationID: e2eConv,
		ClientCommitID: aliceID, Members: []proto.MLSMemberKeyPackage{bob.keyPackage()},
	}))
	bobCreate := commitOf(bob.must(proto.MLSGroupCreate, proto.MLSGroupCreateRequest{
		Permit: bob.permit(), OrgID: e2eOrg, ConversationID: e2eConv,
		ClientCommitID: bobID, Members: []proto.MLSMemberKeyPackage{alice.keyPackage()},
	}))
	alice.confirm(aliceID, proto.MLSCommitOutcomeAccepted, "")

	// Nothing else settles Bob's create: Alice's Commit is another group's and
	// does not apply, and the pending create refuses the join.
	bob.refused(proto.MLSCommitConfirm, proto.MLSCommitConfirmRequest{
		Permit: bob.permit(), OrgID: e2eOrg, ConversationID: e2eConv, ClientCommitID: bobID,
		Outcome: proto.MLSCommitOutcomeSuperseded, WinnerCommitB64: aliceCreate.CommitB64,
	}, proto.ChatMLSErrorCodeFailed)
	join := proto.MLSJoinRequest{Permit: bob.permit(), OrgID: e2eOrg, ConversationID: e2eConv, WelcomeB64: aliceCreate.WelcomeB64}
	bob.refused(proto.MLSJoin, join, proto.ChatMLSErrorCodeCommitPending)

	// Refusals first: another id, and Alice's accepted group. Neither writes.
	bob.refused(proto.MLSGroupDiscardUnaccepted, bob.discardRequest(alice.nextCommitID()), proto.ChatStateErrorCodeConflict)
	bob.assertStatus(bob.status(), 0, bobID)
	alice.refused(proto.MLSGroupDiscardUnaccepted, alice.discardRequest(aliceID), proto.ChatStateErrorCodeConflict)
	alice.assertStatus(alice.status(), 1, "")

	if got := bob.discard(bobID); !got.Discarded {
		t.Fatalf("discard = %+v", got)
	}
	if got := bob.status(); got.HasGroupState || got.CommitPending || got.NeedsRekey || got.Epoch != 0 {
		t.Fatalf("bob's status after the discard = %+v", got)
	}
	if again := bob.discard(bobID); again.Discarded {
		t.Fatalf("discard again = %+v; want nothing to drop", again)
	}
	if bobCreate.WelcomeB64 == "" {
		t.Fatal("bob's create had no welcome; the race did not happen")
	}

	if joined := bob.must(proto.MLSJoin, join).Data.(proto.MLSJoinResponseData); joined.Epoch != 1 {
		t.Fatalf("bob joined alice's group at epoch %d", joined.Epoch)
	}
	c := &dm{alice: alice, bob: bob, seq: 1}
	assertShown(t, c.alice.decrypt(c.send(c.bob, 1, 1, "joined yours")), 0, "joined yours", c.bob, false)
	assertShown(t, c.bob.decrypt(c.send(c.alice, 2, 1, "welcome")), 0, "welcome", c.alice, false)

	// Once joined, the group is confirmed and cannot be discarded.
	bob.refused(proto.MLSGroupDiscardUnaccepted, bob.discardRequest(bobID), proto.ChatStateErrorCodeConflict)
}
