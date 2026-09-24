//go:build mls && cgo

// A device that joins a group after epoch 0 is judged against the server's
// send watermark only for the chain it owns: its own leaf, from the epoch it
// entered at. The server picks that watermark per (conversation, account), so
// a second device of one account is handed the other device's chain, and a
// device that took over a leaf index is handed the chain of the leaf it
// replaced. Neither is this device's, and neither may latch it.

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

// Bob has sent from leaf 1 in epoch 1. His second device joins at epoch 2 as
// leaf 2, and every permit it is handed names leaf 1's chain, first at epoch 1
// and then, once Bob sends again, at epoch 2. None of them is its chain.
func TestMLSChatE2E_ASecondDeviceThatJoinsLaterIsNotLatchedByTheOtherLeaf(t *testing.T) {
	c := newDM(t)
	c.send(c.bob, 1, 1, "one")
	c.send(c.bob, 2, 1, "two")

	bob2 := newTakeoverKeeper(t, c.bob, e2eDevice2)
	oldBob, _, err := keychain.GetMLSLeafNewest(c.alice.store, c.alice.id, c.bob.id)
	if err != nil {
		t.Fatal(err)
	}
	bob2.declare(proto.MLSLeafReasonEnroll, oldBob.NotBefore+60)
	added := commitOf(c.alice.must(proto.MLSCommitBuild, proto.MLSCommitBuildRequest{
		Permit: c.alice.permit(), OrgID: e2eOrg, ConversationID: e2eConv,
		ClientCommitID: c.alice.nextCommitID(), ExpectedEpoch: 1,
		Add: []proto.MLSMemberKeyPackage{bob2.keyPackage()}, UserInitiated: true,
	}))
	c.alice.confirm(added.ClientCommitID, proto.MLSCommitOutcomeAccepted, "")
	c.bob.process(c.nextSeq(), 2, added.CommitB64)

	// The server's record for Bob's account is leaf 1 at epoch 1, two sent.
	joined := mustSucceed(t, "bob2 joins under leaf 1's watermark",
		bob2.joinWith(bob2.withWatermark(1, 1, 2), added.WelcomeB64))
	if got := joined.Data.(proto.MLSJoinResponseData).Epoch; got != 2 {
		t.Fatalf("bob2 joined at epoch %d, want 2", got)
	}

	// Bob sends in epoch 2 first, so the server now names leaf 1 at epoch 2.
	fromBob := c.send(c.bob, 3, 2, "three")
	otherLeaf := bob2.withWatermark(2, 1, 1)
	shown := mustSucceed(t, "bob2 reads under leaf 1's epoch-2 watermark", bob2.decryptWith(otherLeaf, fromBob))
	assertShown(t, shown.Data.(proto.MLSDisplayResponseData), 0, "three", c.bob, false)
	if got := bob2.statusWith(otherLeaf); got.NeedsRekey || got.Epoch != 2 {
		t.Fatalf("bob2's status under another leaf's watermark = %+v", got)
	}

	sent := mustSucceed(t, "bob2 sends under leaf 1's watermark",
		bob2.encryptWith(otherLeaf, messageID(4), 2, "four")).Data.(proto.MLSEncryptResponseData)
	if sent.LeafIndex != 2 {
		t.Fatalf("bob2 sent from leaf %d, want 2", sent.LeafIndex)
	}
	got := c.alice.decrypt(proto.MLSDisplayMessage{Seq: c.nextSeq(), CiphertextB64: sent.CiphertextB64})
	if plaintextOf(t, got.PlaintextB64[0]) != "four" || got.Items[0].SenderDeviceID != e2eDevice2 {
		t.Fatalf("alice read %+v", got.Items[0])
	}

	// Its own chain is still judged: a server claiming leaf 2 sent more than
	// it did latches the conversation, and says why.
	ahead := bob2.withWatermark(2, 2, 5)
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
