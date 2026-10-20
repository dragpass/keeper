//go:build mls && cgo

// What MLS chat holds against a malicious server, and what it does not
// (pre-release security verification, item 4). Each test plays the server
// that decides which Commit, Welcome or message each device sees, through the
// same dispatcher and the real MLS library as the other end-to-end tests.
//
// Some tests pin a limit rather than a guarantee: the server decides delivery,
// so a member it never shows a Commit keeps sending on the epoch it holds.
// Those tests are named for the limit, so a later change that closes it fails
// here and is noticed, and nobody mistakes the limit for a guarantee.

package dispatch

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/dragpass/keeper/internal/keystore/chatstate"
	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/keytransparency"
	"github.com/dragpass/keeper/internal/keystore/mls/mlsadversary"
	"github.com/dragpass/keeper/internal/keystore/proto"
	formatnote "github.com/transparency-dev/formats/note"
	"golang.org/x/mod/sumdb/note"
)

// healthy fails unless k's conversation looks normal at epoch: no latch, no
// sync block, no pending Commit.
func healthy(t *testing.T, k *keeper, epoch uint64) {
	t.Helper()
	st := k.status()
	if st.NeedsRekey || st.SyncBlocked != nil || st.CommitPending || !st.HasGroupState || st.Epoch != epoch {
		t.Fatalf("%s status = %+v; want a healthy group at epoch %d", k.id[:8], st, epoch)
	}
}

// Split view. The server tells Alice and Bob that each one's Commit won
// epoch 3 and shows Carol Alice's. No device can tell on its own: every
// status is healthy. What does tell:
//   - a message across the split does not open, and nothing is written;
//   - the epoch comparison value, compared out of band, differs;
//   - the moment the server shows a device the other Commit for an epoch it
//     confirmed, that device latches fork.
//
// A device the server never shows the other side's Commit or messages is not
// told anything: detection needs the two views to meet.
func TestMLSSplitView_TwoWinnersForOneEpochAreSeenOnlyWhenTheViewsMeet(t *testing.T) {
	r := newRoom(t)
	ua := r.alice.buildUpdate(2)
	ub := r.bob.buildUpdate(2)
	r.alice.confirm(ua.ClientCommitID, proto.MLSCommitOutcomeAccepted, "")
	r.bob.confirm(ub.ClientCommitID, proto.MLSCommitOutcomeAccepted, "")
	rowA := r.nextSeq()
	r.carol.process(rowA, 3, ua.CommitB64)

	for _, k := range []*keeper{r.alice, r.bob, r.carol} {
		healthy(t, k, 3)
	}

	a, b, c := r.alice.epochComparison(), r.bob.epochComparison(), r.carol.epochComparison()
	if a.Epoch != 3 || b.Epoch != 3 || a.DigestB64 != c.DigestB64 || a.DigestB64 == b.DigestB64 {
		t.Fatalf("epoch comparison across the split: alice=%+v bob=%+v carol=%+v", a, b, c)
	}

	fromBob := r.send(r.bob, 1, 3, "on bob's side")
	resp := r.alice.call(proto.MLSDecryptBatchForAppDisplay, r.alice.decryptRequest(fromBob))
	if resp.Success || string(resp.ErrorCode) != string(errs.ErrCodeChatMLSFailed) || resp.Data != nil {
		t.Fatalf("alice opened a message from the other side of the split: %+v", resp)
	}
	fromAlice := r.send(r.alice, 2, 3, "on alice's side")
	resp = r.bob.call(proto.MLSDecryptBatchForAppDisplay, r.bob.decryptRequest(fromAlice))
	if resp.Success || string(resp.ErrorCode) != string(errs.ErrCodeChatMLSFailed) || resp.Data != nil {
		t.Fatalf("bob opened a message from the other side of the split: %+v", resp)
	}
	// Carol is on Alice's side and reads her.
	assertShown(t, r.carol.decrypt(fromAlice), 0, "on alice's side", r.alice, false)
	// A refused message moved nothing: still healthy, still no latch.
	healthy(t, r.alice, 3)
	healthy(t, r.bob, 3)

	// The views meet: the server shows each the other's Commit for epoch 3.
	got := latchedData(t, r.bob.call(proto.MLSProcess, r.bob.processRequest(rowA, 3, ua.CommitB64)))
	if got.RekeyCause != proto.ChatStateRekeyCauseFork || got.RekeyEpoch != 3 {
		t.Fatalf("bob's fork latch = %+v", got)
	}
	got = latchedData(t, r.carol.call(proto.MLSProcess, r.carol.processRequest(r.nextSeq(), 3, ub.CommitB64)))
	if got.RekeyCause != proto.ChatStateRekeyCauseFork || got.RekeyEpoch != 3 {
		t.Fatalf("carol's fork latch = %+v", got)
	}
	// Bob's latch holds: no send, and what he read before stays readable.
	r.bob.refused(proto.MLSEncrypt, r.bob.encryptRequest(messageID(3), 3, "x"),
		string(errs.ErrCodeChatStateRekeyRequired))
	if st := r.bob.status(); !st.NeedsRekey || st.RekeyCause != proto.ChatStateRekeyCauseFork {
		t.Fatalf("bob's status after the fork = %+v", st)
	}
}

// Withheld Commit, the stated limit. Alice (the owner) removes Carol and the
// server accepts it, but shows the row to neither Bob nor Carol. Bob's Keeper
// cannot know the group moved: it encrypts on epoch 2, whose keys Carol still
// holds, and Carol reads it. Alice reads it too, from the epoch-2 secrets she
// retains; nothing marks it as sent after the removal. An honest ariadne
// refuses a new message at a stale epoch (409 CHAT_MLS_EPOCH_STALE); against
// a malicious one, this is the delivery trust the client keeps.
func TestMLSWithheldCommit_AMemberKeptOnTheOldEpochStillEncryptsToTheRemovedMember(t *testing.T) {
	r := newRoom(t)
	removed := r.alice.userRemove(2, e2eCarol)
	r.alice.confirm(removed.ClientCommitID, proto.MLSCommitOutcomeAccepted, "")
	removalRow := r.nextSeq()

	healthy(t, r.bob, 2)
	afterRemoval := r.send(r.bob, 1, 2, "carol should not read this")
	assertShown(t, r.carol.decrypt(afterRemoval), 0, "carol should not read this", r.bob, false)
	assertShown(t, r.alice.decrypt(afterRemoval), 0, "carol should not read this", r.bob, false)

	// What Bob does see: a message of an epoch he does not hold does not open.
	fromAlice := r.send(r.alice, 2, 3, "epoch three")
	resp := r.bob.call(proto.MLSDecryptBatchForAppDisplay, r.bob.decryptRequest(fromAlice))
	if resp.Success || string(resp.ErrorCode) != string(errs.ErrCodeChatMLSFailed) || resp.Data != nil {
		t.Fatalf("bob opened a message of an epoch he never reached: %+v", resp)
	}
	healthy(t, r.bob, 2)

	// Once the server serves the row, Bob catches up and then reads Alice.
	r.bob.process(removalRow, 3, removed.CommitB64)
	assertShown(t, r.bob.decrypt(fromAlice), 0, "epoch three", r.alice, false)
}

// newRoomKeepingWelcome is newRoom that also returns the Welcome Carol
// joined from at epoch 2.
func newRoomKeepingWelcome(t *testing.T) (*room, string) {
	t.Helper()
	c := newDM(t)
	carol := newKeeper(t, e2eCarol)
	add := commitOf(c.alice.must(proto.MLSCommitBuild, proto.MLSCommitBuildRequest{
		Permit: c.alice.permit(), OrgID: e2eOrg, ConversationID: e2eConv,
		ClientCommitID: c.alice.nextCommitID(), ExpectedEpoch: 1,
		Add: []proto.MLSMemberKeyPackage{carol.keyPackage()}, UserInitiated: true,
	}))
	c.alice.confirm(add.ClientCommitID, proto.MLSCommitOutcomeAccepted, "")
	c.bob.process(c.nextSeq(), 2, add.CommitB64)
	carol.must(proto.MLSJoin, proto.MLSJoinRequest{
		Permit: carol.permit(), OrgID: e2eOrg, ConversationID: e2eConv, WelcomeB64: add.WelcomeB64,
	})
	return &room{dm: c, carol: carol}, add.WelcomeB64
}

// Stale removal evidence after a re-add. Carol is removed at epoch 3, forgets
// the removed group, and the owner adds her back at epoch 4. The server then
// replays what it holds from before: the removal row, her first Welcome and
// the re-add Welcome. None of it moves her: she is not told she was removed,
// she keeps her group, and messages still cross. Bob, who applied the
// removal, gets its receipt back for the same row and nothing else.
func TestMLSReplay_OldRemovalAndWelcomesDoNotMoveARejoinedMember(t *testing.T) {
	r, firstWelcome := newRoomKeepingWelcome(t)
	removed := r.alice.userRemove(2, e2eCarol)
	r.alice.confirm(removed.ClientCommitID, proto.MLSCommitOutcomeAccepted, "")
	removalRow := r.nextSeq()
	r.bob.process(removalRow, 3, removed.CommitB64)
	if got := r.carol.process(removalRow, 3, removed.CommitB64); !got.Removed {
		t.Fatalf("carol processed her removal as %+v", got)
	}
	r.carol.forgetRemoved()

	readd := commitOf(r.alice.must(proto.MLSCommitBuild, proto.MLSCommitBuildRequest{
		Permit: r.alice.permit(), OrgID: e2eOrg, ConversationID: e2eConv,
		ClientCommitID: r.alice.nextCommitID(), ExpectedEpoch: 3,
		Add: []proto.MLSMemberKeyPackage{r.carol.keyPackage()}, UserInitiated: true,
	}))
	r.alice.confirm(readd.ClientCommitID, proto.MLSCommitOutcomeAccepted, "")
	r.bob.process(r.nextSeq(), 4, readd.CommitB64)
	if got := r.carol.must(proto.MLSJoin, proto.MLSJoinRequest{
		Permit: r.carol.permit(), OrgID: e2eOrg, ConversationID: e2eConv, WelcomeB64: readd.WelcomeB64,
	}).Data.(proto.MLSJoinResponseData); got.Epoch != 4 {
		t.Fatalf("carol rejoined at epoch %d", got.Epoch)
	}

	// The removal row at its own seq: the fork ring kept the row she applied,
	// so it answers the receipt (removed: false, the account list naming
	// her), which the App never reads as its own removal (chat-sync only acts
	// on other accounts). At a new seq it is stale.
	receipt := r.carol.process(removalRow, 3, removed.CommitB64)
	if receipt.Removed || len(receipt.RemovedAccountIDs) != 1 || receipt.RemovedAccountIDs[0] != e2eCarol {
		t.Fatalf("the replayed removal at its own seq = %+v", receipt)
	}
	r.carol.refused(proto.MLSProcess, r.carol.processRequest(r.nextSeq(), 3, removed.CommitB64),
		string(errs.ErrCodeChatMLSEpochStale))
	healthy(t, r.carol, 4)
	if r.carol.status().RemovedFromGroup {
		t.Fatal("a replayed removal marked the rejoined carol removed")
	}
	// Both Welcomes again.
	for name, w := range map[string]string{"first": firstWelcome, "re-add": readd.WelcomeB64} {
		resp := r.carol.call(proto.MLSJoin, proto.MLSJoinRequest{
			Permit: r.carol.permit(), OrgID: e2eOrg, ConversationID: e2eConv, WelcomeB64: w,
		})
		// Both KeyPackages were consumed at their joins: the pool holds
		// nothing to open either Welcome with.
		if resp.Success || string(resp.ErrorCode) != string(errs.ErrCodeChatMLSWelcomeUnusable) {
			t.Fatalf("the %s Welcome again = %+v", name, resp)
		}
		healthy(t, r.carol, 4)
	}

	// Bob: the exact row returns its receipt; another seq is stale.
	again := r.bob.process(removalRow, 3, removed.CommitB64)
	if again.Removed || len(again.RemovedAccountIDs) != 1 || again.RemovedAccountIDs[0] != e2eCarol {
		t.Fatalf("bob's receipt for the replayed removal = %+v", again)
	}
	r.bob.refused(proto.MLSProcess, r.bob.processRequest(r.nextSeq(), 3, removed.CommitB64),
		string(errs.ErrCodeChatMLSEpochStale))
	healthy(t, r.bob, 4)

	fromCarol := r.send(r.carol, 1, 4, "back in the room")
	assertShown(t, r.bob.decrypt(fromCarol), 0, "back in the room", r.carol, false)
	toCarol := r.send(r.bob, 2, 4, "welcome back")
	assertShown(t, r.carol.decrypt(toCarol), 0, "welcome back", r.bob, false)
}

// Re-add of a removed member by a party without authority. The owner removed
// Carol; Mallory, a plain member, adds her back with a KeyPackage of hers the
// server holds. Alice refuses it and stops at that epoch. Control: when
// Mallory is an admin, the same Commit is applied.
func TestMLSAdversary_APlainMemberReAddsARemovedMember(t *testing.T) {
	for _, admin := range []bool{false, true} {
		r := newAdvRoom(t, admin)
		removal := r.alice.userRemove(1, e2eCarol)
		r.alice.confirm(removal.ClientCommitID, proto.MLSCommitOutcomeAccepted, "")
		if got := r.adv.Process(unb64(t, removal.CommitB64)); got != 2 {
			t.Fatalf("the adversary followed the removal to epoch %d", got)
		}
		r.nextSeq()
		readd, _ := r.adv.Build(mlsadversary.Commit{Adds: [][]byte{keyPackageBytes(t, r.carol.keyPackage())}})
		req := r.alice.processRequest(r.nextSeq(), 3, advB64(readd))
		req.CommitAttestation = attested(e2eAlice, e2eCarol, advMallory)
		if admin {
			if got := r.alice.must(proto.MLSProcess, req).Data.(proto.MLSProcessResponseData); got.Epoch != 3 {
				t.Fatalf("alice applied the admin's re-add at %+v", got)
			}
			continue
		}
		got := blockedData(t, r.alice.call(proto.MLSProcess, req))
		if got.Cause != proto.ChatStateRekeyCauseUnauthorizedCommit || got.CommitterAccountID != advMallory || got.Epoch != 3 {
			t.Fatalf("alice blocked %+v; want unauthorized_commit at 3 naming mallory", got)
		}
		if st := r.alice.status(); st.Epoch != 2 || st.NeedsRekey || st.SyncBlocked == nil {
			t.Fatalf("alice after the refused re-add = %+v", st)
		}
	}
}

// History is not migrated to a device that takes over the seat (policy:
// a new device opens only messages after its join is confirmed). The takeover
// device reads a message from before the replace as before_join, with no
// plaintext and no sender, and the rest of the page is shown.
func TestMLSTakeover_TheNewDeviceDoesNotOpenHistoryFromBeforeItsJoin(t *testing.T) {
	c := newDM(t)
	before := c.send(c.alice, 1, 1, "before the takeover")
	assertShown(t, c.bob.decrypt(before), 0, "before the takeover", c.alice, false)
	oldBob, _, err := keychain.GetMLSLeafNewest(c.alice.store, c.alice.id, c.bob.id)
	if err != nil {
		t.Fatal(err)
	}
	bob2 := newTakeoverKeeper(t, c.bob, e2eDevice2)
	epoch := c.takeOver(c.bob, bob2, 1, oldBob.NotBefore+60)

	after := c.send(c.alice, 2, epoch, "after the takeover")
	got := bob2.decrypt(before, after)
	if got.Items[0].State != proto.MLSDisplayItemStateBeforeJoin || got.PlaintextB64[0] != "" ||
		got.Items[0].SenderAccountID != "" {
		t.Fatalf("the takeover device read the earlier message as %+v %q", got.Items[0], got.PlaintextB64[0])
	}
	assertShown(t, got, 1, "after the takeover", c.alice, false)
}

// A Welcome of another conversation's group, handed to a device for this
// conversation, is refused and writes nothing; the same Welcome joins under
// its own conversation id.
func TestMLSMaliciousWelcome_AnotherConversationsWelcomeIsRefused(t *testing.T) {
	e2eStateRoot(t)
	carol, mallory := newKeeper(t, e2eCarol), newKeeper(t, advMallory)
	adv := mlsadversary.Start(t, leafKeyOf(t, mallory), true)
	adv.Create([]byte(e2eConv2), chatstate.Roles{Kind: chatstate.RolesKindRoom, Owner: advMallory}.Encode())
	_, welcome := adv.Build(mlsadversary.Commit{Adds: [][]byte{keyPackageBytes(t, carol.keyPackage())}, Apply: true})
	assertCode(t, carol.call(proto.MLSJoin, proto.MLSJoinRequest{
		Permit: carol.permit(), OrgID: e2eOrg, ConversationID: e2eConv, WelcomeB64: advB64(welcome),
	}), string(errs.ErrCodeChatMLSFailed))
	if st := carol.status(); st.HasGroupState || st.NeedsRekey {
		t.Fatalf("carol after the refused join = %+v", st)
	}
	if n := carol.poolSize(); n != 1 {
		t.Fatalf("carol's pool holds %d after the refused join; want the entry kept", n)
	}
}

// Message replay and cross-room replay. A message re-served at the same seq
// comes from the local history; the same bytes under a new seq do not open a
// second time; a message of another conversation's group does not open in
// this one. Reordering inside an epoch is not refused: each message is
// authenticated to its sender and position, and display order is the
// server's seq.
func TestMLSReplay_MessagesReplayedOrMovedAcrossRoomsDoNotOpenAgain(t *testing.T) {
	c := newDM(t)
	first := c.send(c.alice, 1, 1, "one")
	second := c.send(c.alice, 2, 1, "two")
	assertShown(t, c.bob.decrypt(second), 0, "two", c.alice, false)
	assertShown(t, c.bob.decrypt(first), 0, "one", c.alice, false)
	assertShown(t, c.bob.decrypt(first), 0, "one", c.alice, true)

	moved := proto.MLSDisplayMessage{Seq: c.nextSeq(), CiphertextB64: first.CiphertextB64}
	// Its key was consumed at the first delivery.
	resp := c.bob.call(proto.MLSDecryptBatchForAppDisplay, c.bob.decryptRequest(moved))
	if resp.Success || string(resp.ErrorCode) != string(errs.ErrCodeChatMLSFailed) || resp.Data != nil {
		t.Fatalf("the same message under a new seq = %+v", resp)
	}

	// A second conversation between the same two accounts.
	other := conversation(c.alice, e2eConv2)
	otherBob := conversation(c.bob, e2eConv2)
	id := c.alice.nextCommitID()
	created := commitOf(c.alice.must(proto.MLSGroupCreate, proto.MLSGroupCreateRequest{
		Permit: other.permit, Roles: roleSet(c.alice.id), OrgID: e2eOrg, ConversationID: e2eConv2,
		ClientCommitID: id, Members: []proto.MLSMemberKeyPackage{c.bob.keyPackage()},
	}))
	c.alice.must(proto.MLSCommitConfirm, proto.MLSCommitConfirmRequest{
		Permit: other.permit, OrgID: e2eOrg, ConversationID: e2eConv2,
		ClientCommitID: id, Outcome: proto.MLSCommitOutcomeAccepted,
	})
	c.bob.must(proto.MLSJoin, proto.MLSJoinRequest{
		Permit: otherBob.permit, OrgID: e2eOrg, ConversationID: e2eConv2, WelcomeB64: created.WelcomeB64,
	})
	sent := c.alice.must(proto.MLSEncrypt, proto.MLSEncryptRequest{
		Permit: other.permit, OrgID: e2eOrg, ConversationID: e2eConv2, ClientMessageID: messageID(9),
		ExpectedEpoch: 1, PlaintextB64: base64.StdEncoding.EncodeToString([]byte("other room")),
	}).Data.(proto.MLSEncryptResponseData)
	crossed := proto.MLSDisplayMessage{Seq: c.nextSeq(), CiphertextB64: sent.CiphertextB64}
	resp = c.bob.call(proto.MLSDecryptBatchForAppDisplay, c.bob.decryptRequest(crossed))
	if resp.Success || string(resp.ErrorCode) != string(errs.ErrCodeChatMLSFailed) || resp.Data != nil {
		t.Fatalf("a message of another room opened in this one: %+v", resp)
	}
	healthy(t, c.bob, 1)
}

// conversationPermit is a permit of k's for another conversation id.
type conversationPermit struct{ permit proto.ChatStatePermit }

func conversation(k *keeper, conv string) conversationPermit {
	p := k.permit()
	p.ConversationID = conv
	return conversationPermit{permit: p}
}

func leafDeclarationOf(t *testing.T, k *keeper) proto.MLSLeafDeclaration {
	t.Helper()
	var decl proto.MLSLeafDeclaration
	if err := json.Unmarshal(leafKeyOf(t, k).Declaration, &struct {
		Declaration *proto.MLSLeafDeclaration `json:"declaration"`
	}{&decl}); err != nil {
		t.Fatal(err)
	}
	return decl
}

// ktTrust is a Key Transparency trust file's content with fresh log and
// witness keys: enough to switch the gate on. Nothing is ever logged under
// it, so every proof the gate asks for is missing.
func ktTrust(t *testing.T) *keytransparency.Trust {
	t.Helper()
	_, logPublic, err := note.GenerateKey(rand.Reader, "dragpass.test/log")
	if err != nil {
		t.Fatal(err)
	}
	logVerifier, err := note.NewVerifier(logPublic)
	if err != nil {
		t.Fatal(err)
	}
	witnesses := make([]note.Verifier, 3)
	for i := range witnesses {
		_, public, err := note.GenerateKey(rand.Reader, fmt.Sprintf("w%d.witness", i))
		if err != nil {
			t.Fatal(err)
		}
		if witnesses[i], err = formatnote.NewVerifierForCosignatureV1(public); err != nil {
			t.Fatal(err)
		}
	}
	return &keytransparency.Trust{
		Origin: "dragpass.test/log", LogVerifier: logVerifier, WitnessVerifiers: witnesses,
		Quorum: 2, MaxCheckpointAge: time.Hour, FutureSkew: time.Minute,
	}
}

func (k *keeper) evaluatePeer(account, pem string) proto.BaseResponse {
	k.t.Helper()
	return k.call(proto.ActionPeerKeyChainEvaluate, proto.PeerKeyChainEvaluateRequest{
		OwnerAccountID: k.id, AccountID: account, PublicKey: pem,
	})
}

// Key Transparency and a Welcome's tree, the stated limit (protocol.md, "Key
// Transparency": the leaves a Welcome's tree already holds are not entering
// leaves and need no proof). With the gate on, a modified client creates a
// room holding Alice and a leaf that claims Bob's account under a key Bob
// never had. Alice has never seen Bob, joins with no proof at all, and pins
// that key on first use.
//
// The pin is the one the wrap actions read. A Keeper with the gate on and no
// pin for Bob refuses to take that key without Bob's enrollment proof
// (0.0.57, "First peer pin with Key Transparency"); Alice's Keeper, after the
// join, accepts it as the pinned key, with no proof. Pinned here so the gap
// between the two first-pin rules is not mistaken for a guarantee.
func TestMLSKeyTransparency_AWelcomeTreeLeafIsPinnedWithoutAProofAndTheWrapPathTrustsThatPin(t *testing.T) {
	e2eStateRoot(t)
	trust := ktTrust(t)
	alice, impostor, mallory := newKeeper(t, e2eAlice), newKeeper(t, e2eBob), newKeeper(t, advMallory)
	alice.deps.KeyTransparency = keytransparency.Gate{Trust: trust}
	fresh := newKeeper(t, e2eAlice)
	fresh.root = filepath.Join(t.TempDir(), "fresh")
	fresh.deps.KeyTransparency = keytransparency.Gate{Trust: trust}
	impostorPEM := impostor.publicKeyPEM()

	// Control: with the gate on and no pin, the impostor's key needs a proof.
	if resp := fresh.evaluatePeer(e2eBob, impostorPEM); resp.Success ||
		string(resp.ErrorCode) != "key_transparency_unverified" {
		t.Fatalf("a first pin without a proof = %+v; want key_transparency_unverified", resp)
	}

	adv := mlsadversary.Start(t, leafKeyOf(t, mallory), true)
	adv.Create([]byte(e2eConv), chatstate.Roles{Kind: chatstate.RolesKindRoom, Owner: advMallory}.Encode())
	_, welcome := adv.Build(mlsadversary.Commit{Adds: [][]byte{
		keyPackageBytes(t, alice.keyPackage()), keyPackageBytes(t, impostor.keyPackage()),
	}, Apply: true})
	joined := alice.must(proto.MLSJoin, proto.MLSJoinRequest{
		Permit: alice.permit(), OrgID: e2eOrg, ConversationID: e2eConv, WelcomeB64: advB64(welcome),
	}).Data.(proto.MLSJoinResponseData)
	if joined.Epoch != 1 {
		t.Fatalf("alice joined at %+v", joined)
	}
	pin, err := keychain.GetPeerKeyPin(alice.store, e2eAlice, e2eBob)
	if err != nil || pin.Fingerprint != crypto.AccountKeyFingerprint([]byte(impostorPEM)) ||
		pin.State != keychain.PeerKeyPinStateTOFU {
		t.Fatalf("alice's pin for bob after the join = %+v, %v", pin, err)
	}
	resp := alice.evaluatePeer(e2eBob, impostorPEM)
	if !resp.Success {
		t.Fatalf("the wrap path's evaluation of the pinned key = %+v", resp)
	}
	if got := resp.Data.(proto.PeerKeyChainEvaluateResponseData); got.State != string(keychain.PeerKeyPinStateTOFU) || got.Advanced {
		t.Fatalf("the wrap path took the joined pin as %+v", got)
	}
}
