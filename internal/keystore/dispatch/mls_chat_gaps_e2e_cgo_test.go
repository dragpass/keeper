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

	"github.com/dragpass/keeper/internal/keystore/logger"
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

	// mls_mark_sent never ran: the process died after the POST. The page is
	// not refused. The row carries the exact bytes of Alice's outbox entry, so
	// the batch binds her sealed copy to its seq and shows it from there, and
	// Bob's message is delivered beside it.
	got := c.alice.decrypt(own, theirs)
	assertShown(t, got, 0, "from alice", c.alice, true)
	assertShown(t, got, 1, "from bob", c.bob, false)
	if got.Items[0].State != proto.MLSDisplayItemStateShown || got.Items[1].State != proto.MLSDisplayItemStateShown {
		t.Fatalf("item states = %q, %q", got.Items[0].State, got.Items[1].State)
	}
	// The late mark sent finds the pair already bound and writes nothing.
	if late := c.alice.markSent(messageID(1), own.Seq); late.Bound {
		t.Fatalf("mark sent after the display bind = %+v; want nothing written", late)
	}
	// The same bytes under another seq do not move the copy: that row has no
	// copy of its own.
	dup := proto.MLSDisplayMessage{Seq: c.nextSeq(), CiphertextB64: own.CiphertextB64}
	if got := c.alice.decrypt(dup); got.PlaintextB64[0] != "" ||
		got.Items[0].State != proto.MLSDisplayItemStateOwnWithoutCopy ||
		got.Items[0].SenderAccountID != c.alice.id || got.Items[0].SenderDeviceID != e2eDevice ||
		got.Items[0].FromHistory {
		t.Fatalf("own bytes under a second seq = %q %+v", got.PlaintextB64[0], got.Items[0])
	}

	// The ordinary order: mark sent binds first, the display reads the copy.
	second := c.alice.encrypt(messageID(3), 1, "marked first")
	marked := proto.MLSDisplayMessage{Seq: c.nextSeq(), CiphertextB64: second.CiphertextB64}
	if bound := c.alice.markSent(messageID(3), marked.Seq); !bound.Bound {
		t.Fatalf("mark sent = %+v", bound)
	}
	if again := c.alice.markSent(messageID(3), marked.Seq); again.Bound {
		t.Fatalf("mark sent again = %+v; want nothing written", again)
	}
	assertShown(t, c.alice.decrypt(marked), 0, "marked first", c.alice, true)

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

// ────────────────────────────────────────────────────────────────────────
// 3. A room name sealed under the epoch's exporter and resealed by the
//    committer.
// ────────────────────────────────────────────────────────────────────────

const e2eCarol = "c3333333-3333-4333-8333-333333333333"

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

type sealedName struct {
	epoch    uint64
	iv, ct   string
	resealed bool
}

func nameOf(r proto.MLSCommitResponseData) sealedName {
	return sealedName{epoch: r.NameEpoch, iv: r.NameIVb64, ct: r.NameCiphertextB64, resealed: r.NameCiphertextB64 != ""}
}

func (k *keeper) sealName(name string) sealedName {
	k.t.Helper()
	got := k.must(proto.MLSRoomNameSeal, proto.MLSRoomNameSealRequest{
		Permit: k.permit(), OrgID: e2eOrg, ConversationID: e2eConv, PlaintextB64: b64(name),
	}).Data.(proto.MLSRoomNameSealResponseData)
	return sealedName{epoch: got.Epoch, iv: got.NameIVb64, ct: got.NameCiphertextB64}
}

func (k *keeper) openNameRequest(n sealedName) proto.MLSRoomNameOpenRequest {
	return proto.MLSRoomNameOpenRequest{
		Permit: k.permit(), OrgID: e2eOrg, ConversationID: e2eConv,
		Epoch: n.epoch, NameIVb64: n.iv, NameCiphertextB64: n.ct,
	}
}

func (k *keeper) openName(n sealedName) string {
	k.t.Helper()
	got := k.must(proto.MLSRoomNameOpen, k.openNameRequest(n)).Data.(proto.MLSDisplayResponseData)
	if len(got.PlaintextB64) != 1 || got.Items != nil {
		k.t.Fatalf("room name open answered %d entries and items %v", len(got.PlaintextB64), got.Items)
	}
	return plaintextOf(k.t, got.PlaintextB64[0])
}

func TestMLSChatE2E_ARoomNameFollowsTheEpochThroughEveryCommit(t *testing.T) {
	e2eStateRoot(t)
	alice, bob, carol := newKeeper(t, e2eAlice), newKeeper(t, e2eBob), newKeeper(t, e2eCarol)
	const name = "설계 리뷰 방"

	// The create reseals the name for epoch 1; the epoch 0 name the server
	// stores at room creation is sealed while the create is pending.
	id := alice.nextCommitID()
	createReq := proto.MLSGroupCreateRequest{
		Permit: alice.permit(), OrgID: e2eOrg, ConversationID: e2eConv,
		ClientCommitID: id, Members: []proto.MLSMemberKeyPackage{bob.keyPackage()},
		RoomNamePlaintextB64: b64(name),
	}
	create := commitOf(alice.must(proto.MLSGroupCreate, createReq))
	first := nameOf(create)
	if !first.resealed || first.epoch != 1 {
		t.Fatalf("group create name = %+v", first)
	}
	if zero := alice.sealName(name); zero.epoch != 0 || alice.openName(zero) != name {
		t.Fatalf("epoch 0 name = %+v", zero)
	}
	// A retried create reseals again under a fresh IV, for the same epoch.
	if again := nameOf(commitOf(alice.must(proto.MLSGroupCreate, createReq))); again.epoch != 1 || again.iv == first.iv {
		t.Fatalf("retried create name = %+v", again)
	}
	alice.confirm(id, proto.MLSCommitOutcomeAccepted, "")
	bob.must(proto.MLSJoin, proto.MLSJoinRequest{
		Permit: bob.permit(), OrgID: e2eOrg, ConversationID: e2eConv, WelcomeB64: create.WelcomeB64,
	})
	if got := alice.openName(first); got != name {
		t.Fatalf("alice opened %q at epoch 1", got)
	}
	if got := bob.openName(first); got != name {
		t.Fatalf("bob, a joiner from the create's Welcome, opened %q", got)
	}

	// An Add carries the name into epoch 2, computed before the CAS.
	add := commitOf(alice.must(proto.MLSCommitBuild, proto.MLSCommitBuildRequest{
		Permit: alice.permit(), OrgID: e2eOrg, ConversationID: e2eConv,
		ClientCommitID: alice.nextCommitID(), ExpectedEpoch: 1,
		Add: []proto.MLSMemberKeyPackage{carol.keyPackage()}, UserInitiated: true, RoomNamePlaintextB64: b64(name),
	}))
	second := nameOf(add)
	if !second.resealed || second.epoch != 2 {
		t.Fatalf("add commit name = %+v", second)
	}
	// Not openable until the epoch is really 2 on this device.
	alice.refused(proto.MLSRoomNameOpen, alice.openNameRequest(second), proto.ChatMLSErrorCodeEpochStale)
	alice.confirm(add.ClientCommitID, proto.MLSCommitOutcomeAccepted, "")
	bob.process(2, 2, add.CommitB64)
	carol.must(proto.MLSJoin, proto.MLSJoinRequest{
		Permit: carol.permit(), OrgID: e2eOrg, ConversationID: e2eConv, WelcomeB64: add.WelcomeB64,
	})
	for who, k := range map[string]*keeper{"the committer": alice, "a member who processed it": bob, "the joiner": carol} {
		if got := k.openName(second); got != name {
			t.Fatalf("%s opened %q at epoch 2", who, got)
		}
		// The previous epoch's exporter is gone.
		k.refused(proto.MLSRoomNameOpen, k.openNameRequest(first), proto.ChatMLSErrorCodeEpochStale)
	}

	// A rename at the confirmed epoch, and an Update that reseals it.
	renamed := bob.sealName("새 이름")
	if renamed.epoch != 2 || carol.openName(renamed) != "새 이름" {
		t.Fatalf("rename = %+v", renamed)
	}
	update := commitOf(carol.must(proto.MLSCommitBuild, proto.MLSCommitBuildRequest{
		Permit: carol.permit(), OrgID: e2eOrg, ConversationID: e2eConv,
		ClientCommitID: carol.nextCommitID(), ExpectedEpoch: 2, UpdateSelf: true,
		RoomNamePlaintextB64: b64("새 이름"),
	}))
	carol.confirm(update.ClientCommitID, proto.MLSCommitOutcomeAccepted, "")
	alice.process(3, 3, update.CommitB64)
	if got := alice.openName(nameOf(update)); got != "새 이름" {
		t.Fatalf("alice opened %q at epoch 3", got)
	}
	alice.refused(proto.MLSRoomNameOpen, alice.openNameRequest(renamed), proto.ChatMLSErrorCodeEpochStale)

	// An altered name is refused with no plaintext.
	bad := nameOf(update)
	ct, _ := base64.StdEncoding.DecodeString(bad.ct)
	ct[0] ^= 1
	bad.ct = base64.StdEncoding.EncodeToString(ct)
	resp := alice.call(proto.MLSRoomNameOpen, alice.openNameRequest(bad))
	if resp.Success || string(resp.ErrorCode) != proto.ChatMLSErrorCodeFailed || resp.Data != nil {
		t.Fatalf("an altered name = %+v", resp)
	}
	for _, k := range []*keeper{alice, bob, carol} {
		for _, text := range []string{name, "새 이름"} {
			if k.deps.Logger.(*logger.MemoryLogger).Contains(text) {
				t.Fatalf("%s's log carries a room name", k.id[:8])
			}
		}
	}
}

// A DM gives no name and gets none back.
func TestMLSChatE2E_ACommitWithoutANameCarriesNone(t *testing.T) {
	c := newDM(t)
	if got := nameOf(c.alice.buildUpdate(1)); got.resealed || got.epoch != 0 || got.iv != "" {
		t.Fatalf("an update without a name = %+v", got)
	}
}
