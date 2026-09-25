//go:build mls && cgo

// A device that joins a group after epoch 0 is judged against the server's
// send watermark only for the chain it owns: its own leaf, from the epoch it
// entered at. The server picks that watermark per (conversation, account), so
// a device that took an account's seat is handed the chain of the leaf it
// replaced, on that leaf's index or on another one. It is not this device's,
// and it may not latch it.

package dispatch

import (
	"encoding/base64"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// withWatermark is k's permit carrying the server's claim about one leaf's
// application chain.
func (k *keeper) withWatermark(epoch uint64, leaf uint32, nextApplication uint64) proto.ChatStatePermit {
	p := k.permit()
	p.WatermarkEpoch, p.WatermarkLeafIndex, p.WatermarkNextApplication = epoch, leaf, nextApplication
	return p
}

func (k *keeper) joinWith(p proto.ChatStatePermit, welcomeB64 string) proto.BaseResponse {
	k.t.Helper()
	return k.call(proto.MLSJoin, proto.MLSJoinRequest{
		Permit: p, OrgID: e2eOrg, ConversationID: e2eConv, WelcomeB64: welcomeB64,
	})
}

func (k *keeper) encryptWith(p proto.ChatStatePermit, id string, epoch uint64, text string) proto.BaseResponse {
	k.t.Helper()
	return k.call(proto.MLSEncrypt, proto.MLSEncryptRequest{
		Permit: p, OrgID: e2eOrg, ConversationID: e2eConv,
		ClientMessageID: id, ExpectedEpoch: epoch,
		PlaintextB64: base64.StdEncoding.EncodeToString([]byte(text)),
	})
}

func (k *keeper) decryptWith(p proto.ChatStatePermit, msgs ...proto.MLSDisplayMessage) proto.BaseResponse {
	k.t.Helper()
	return k.call(proto.MLSDecryptBatchForAppDisplay, proto.MLSDecryptBatchForAppDisplayRequest{
		Permit: p, OrgID: e2eOrg, ConversationID: e2eConv, Messages: msgs,
	})
}

func mustSucceed(t *testing.T, what string, resp proto.BaseResponse) proto.BaseResponse {
	t.Helper()
	if !resp.Success {
		t.Fatalf("%s: %s (%s)", what, resp.Error, resp.ErrorCode)
	}
	return resp
}

// One active device per account, so a second device of an account never
// sits beside the first: it takes the first one's place. When the leaf it
// adds lands on another index than the one it removes (an index freed
// earlier is filled first), the server's watermark for the account is still
// the old leaf's chain on the old index. Bob sent twice from leaf 2 in epoch
// 1; Carol's removal left leaf 1 blank in epoch 2; Bob2 takes Bob's seat in
// epoch 3 as leaf 1, and every permit it is handed names leaf 2's chain at
// epoch 1. That chain is not Bob2's.
func TestMLSChatE2E_ASecondDeviceThatJoinsLaterIsNotLatchedByTheOtherLeaf(t *testing.T) {
	e2eStateRoot(t)
	alice, carol, bob := newKeeper(t, e2eAlice), newKeeper(t, e2eCarol), newKeeper(t, e2eBob)
	created := alice.nextCommitID()
	first := commitOf(alice.must(proto.MLSGroupCreate, proto.MLSGroupCreateRequest{
		Permit: alice.permit(), OrgID: e2eOrg, ConversationID: e2eConv, ClientCommitID: created,
		Members: []proto.MLSMemberKeyPackage{carol.keyPackage(), bob.keyPackage()},
		Roles:   roleSet(e2eAlice),
	}))
	alice.confirm(created, proto.MLSCommitOutcomeAccepted, "")
	for _, k := range []*keeper{carol, bob} {
		k.must(proto.MLSJoin, proto.MLSJoinRequest{
			Permit: k.permit(), OrgID: e2eOrg, ConversationID: e2eConv, WelcomeB64: first.WelcomeB64,
		})
	}
	c := &dm{alice: alice, bob: bob, seq: 1}
	if sent := bob.encrypt(messageID(1), 1, "one"); sent.LeafIndex != 2 {
		t.Fatalf("bob sent from leaf %d; the test needs him on leaf 2", sent.LeafIndex)
	}
	c.nextSeq()
	c.send(bob, 2, 1, "two")

	removeCarol := alice.buildRequest(1)
	removeCarol.RemoveAccountIDs, removeCarol.UserInitiated = []string{e2eCarol}, true
	removed := alice.accepted(removeCarol)
	bob.process(c.nextSeq(), 2, removed.CommitB64)

	bob2 := newTakeoverKeeper(t, bob, e2eDevice2)
	oldBob, _, err := keychain.GetMLSLeafNewest(alice.store, alice.id, bob.id)
	if err != nil {
		t.Fatal(err)
	}
	decl := bob2.declare(proto.MLSLeafReasonRotate, oldBob.NotBefore+60)
	alice.replacing = []proto.ChatStateLeafReplacement{{AccountID: bob.id, NewSignatureKeyFP: decl.SignatureKeyFingerprint}}
	bob2.replacing = alice.replacing
	replace := alice.buildRequest(2)
	replace.Replace = []proto.MLSReplaceMember{approved(bob2.keyPackage(), bob.handoverFor(decl))}
	taken := alice.accepted(replace)
	alice.replacing, bob2.replacing = nil, nil

	// The server's record for Bob's account is leaf 2 at epoch 1, two sent.
	oldChain := bob2.withWatermark(1, 2, 2)
	joined := mustSucceed(t, "bob2 joins under leaf 2's watermark", bob2.joinWith(oldChain, taken.WelcomeB64))
	if got := joined.Data.(proto.MLSJoinResponseData).Epoch; got != 3 {
		t.Fatalf("bob2 joined at epoch %d, want 3", got)
	}

	fromAlice := c.send(alice, 3, 3, "three")
	shown := mustSucceed(t, "bob2 reads under leaf 2's watermark", bob2.decryptWith(oldChain, fromAlice))
	assertShown(t, shown.Data.(proto.MLSDisplayResponseData), 0, "three", alice, false)
	if got := bob2.statusWith(oldChain); got.NeedsRekey || got.Epoch != 3 {
		t.Fatalf("bob2's status under another leaf's watermark = %+v", got)
	}

	sent := mustSucceed(t, "bob2 sends under leaf 2's watermark",
		bob2.encryptWith(oldChain, messageID(4), 3, "four")).Data.(proto.MLSEncryptResponseData)
	if sent.LeafIndex != 1 {
		t.Fatalf("bob2 sent from leaf %d; the test needs the freed index 1", sent.LeafIndex)
	}
	got := alice.decrypt(proto.MLSDisplayMessage{Seq: c.nextSeq(), CiphertextB64: sent.CiphertextB64})
	if plaintextOf(t, got.PlaintextB64[0]) != "four" || got.Items[0].SenderDeviceID != e2eDevice2 {
		t.Fatalf("alice read %+v", got.Items[0])
	}

	// Its own chain is still judged: a server claiming leaf 1 sent more than
	// it did latches the conversation, and says why.
	ahead := bob2.withWatermark(3, 1, 5)
	if got := bob2.statusWith(ahead); !got.NeedsRekey || got.RekeyCause != proto.ChatStateRekeyCauseWatermarkAhead {
		t.Fatalf("bob2's status under a watermark ahead of its own leaf = %+v", got)
	}
}

// Bob2 takes over Bob's leaf through a replace, and the new leaf lands on the
// index Bob's old leaf left. The server's watermark for the account is still
// Bob's old chain on that index at epoch 1. Bob2 entered at epoch 2, so that
// chain is not its own even though the index is.
func TestMLSChatE2E_ATakeoverDeviceIsNotLatchedByTheLeafItReplaced(t *testing.T) {
	c := newDM(t)
	c.send(c.bob, 1, 1, "one")
	c.send(c.bob, 2, 1, "two")

	bob2 := newTakeoverKeeper(t, c.bob, e2eDevice2)
	oldBob, _, err := keychain.GetMLSLeafNewest(c.alice.store, c.alice.id, c.bob.id)
	if err != nil {
		t.Fatal(err)
	}
	decl := bob2.declare(proto.MLSLeafReasonRotate, oldBob.NotBefore+60)
	c.alice.replacing = []proto.ChatStateLeafReplacement{{AccountID: c.bob.id, NewSignatureKeyFP: decl.SignatureKeyFingerprint}}
	bob2.replacing = c.alice.replacing
	built := commitOf(c.alice.must(proto.MLSCommitBuild, proto.MLSCommitBuildRequest{
		Permit: c.alice.permit(), OrgID: e2eOrg, ConversationID: e2eConv,
		ClientCommitID: c.alice.nextCommitID(), ExpectedEpoch: 1,
		Replace: []proto.MLSReplaceMember{approved(bob2.keyPackage(), c.bob.handoverFor(decl))},
	}))
	c.alice.confirm(built.ClientCommitID, proto.MLSCommitOutcomeAccepted, "")

	oldChain := bob2.withWatermark(1, 1, 2)
	mustSucceed(t, "bob2 joins under the replaced leaf's watermark", bob2.joinWith(oldChain, built.WelcomeB64))
	sent := mustSucceed(t, "bob2 sends under the replaced leaf's watermark",
		bob2.encryptWith(oldChain, messageID(3), 2, "three")).Data.(proto.MLSEncryptResponseData)
	if sent.LeafIndex != 1 {
		t.Fatalf("bob2 sent from leaf %d; the test needs the replaced index 1", sent.LeafIndex)
	}
	if got := bob2.statusWith(oldChain); got.NeedsRekey {
		t.Fatalf("bob2's status under the replaced leaf's watermark = %+v", got)
	}
}

// One active device per account: the room's owner cannot add Bob's second
// device beside his first. Nothing is built.
func TestMLSChatE2E_ASecondDeviceIsNotAddedBesideTheFirst(t *testing.T) {
	r := newRolesRoom(t)
	bob2 := newTakeoverKeeper(t, r.bob, e2eDevice2)
	oldBob, _, err := keychain.GetMLSLeafNewest(r.alice.store, r.alice.id, r.bob.id)
	if err != nil {
		t.Fatal(err)
	}
	bob2.declare(proto.MLSLeafReasonEnroll, oldBob.NotBefore+60)
	add := r.alice.buildRequest(1)
	add.Add, add.UserInitiated = []proto.MLSMemberKeyPackage{bob2.keyPackage()}, true
	assertCode(t, r.alice.call(proto.MLSCommitBuild, add), proto.ChatMLSErrorCodeCommitUnauthorized)
	if got := r.alice.status(); got.CommitPending || got.Epoch != 1 {
		t.Fatalf("alice after the refused add = %+v", got)
	}
}
