//go:build mls && cgo

// M4.4 device takeover end to end through the dispatcher, with three Keeper
// stores: Alice, Bob, and Bob's new device Bob2. Bob2 shares Bob's account key
// and nothing else — its own keyring and its own chat state root, as a new
// machine would have. The test stands in for ariadne: it accepts Bob2's
// rotate, lists the takeover in the permits it signs, and accepts Alice's
// replace Commit.

package dispatch

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/chatstate"
	"github.com/dragpass/keeper/internal/keystore/handlers"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/logger"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/verifier"
)

const e2eDevice2 = "d2222222-2222-4222-8222-222222222222"

// newTakeoverKeeper is a new machine of of's account: the account key pair and
// nothing else. No leaf is enrolled.
func newTakeoverKeeper(t *testing.T, of *keeper, device string) *keeper {
	t.Helper()
	store := keychain.NewMemorySecretStore()
	priv, err := keychain.GetPrivateKey(of.store)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := keychain.GetPublicKey(of.store)
	if err != nil {
		t.Fatal(err)
	}
	if err := keychain.SavePrivateKey(store, priv); err != nil {
		t.Fatal(err)
	}
	if err := keychain.SavePublicKey(store, pub); err != nil {
		t.Fatal(err)
	}
	return &keeper{
		t: t, id: of.id, device: device, store: store,
		root: filepath.Join(t.TempDir(), "chat-state-"+device[:8]),
		deps: handlers.Deps{
			Logger:            logger.NewMemoryLogger(),
			Store:             store,
			ServerKeyVerifier: verifier.AlwaysOKVerifier{},
		},
	}
}

func (k *keeper) buildReplace(expected uint64, members ...proto.MLSReplaceMember) proto.BaseResponse {
	k.t.Helper()
	return k.call(proto.MLSCommitBuild, proto.MLSCommitBuildRequest{
		Permit: k.permit(), OrgID: e2eOrg, ConversationID: e2eConv,
		ClientCommitID: k.nextCommitID(), ExpectedEpoch: expected, Replace: members,
	})
}

// storedGroupState reads the group state this Keeper's record holds, from its
// own root.
func (k *keeper) storedGroupState() []byte {
	k.t.Helper()
	if k.root != "" {
		k.t.Setenv(chatstate.RootEnvVar, k.root)
	}
	store, err := chatstate.Open(k.store, k.id)
	if err != nil {
		k.t.Fatal(err)
	}
	defer store.Close()
	blob, err := store.LoadGroupState(e2eConv, chatstate.ServerWatermark{})
	if err != nil {
		k.t.Fatal(err)
	}
	return blob
}

func assertReplacementLatch(t *testing.T, k *keeper, want ...proto.ChatStateLeafReplacement) {
	t.Helper()
	got := k.status().LeafReplacementLatch
	if got == nil || len(got) != len(want) {
		t.Fatalf("%s leaf replacement latch = %v; want %v", k.id[:8], got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("%s leaf replacement latch = %v; want %v", k.id[:8], got, want)
		}
	}
}

func replaceOf(kp proto.MLSMemberKeyPackage) proto.MLSReplaceMember {
	return proto.MLSReplaceMember{AccountID: kp.AccountID, KeyPackageB64: kp.KeyPackageB64}
}

func TestMLSChatE2E_ANewDeviceTakesOverAndTheOldOneIsRemoved(t *testing.T) {
	// 1. Alice and Bob are in a DM.
	c := newDM(t)
	before := c.send(c.alice, 1, 1, "before the takeover")
	assertShown(t, c.bob.decrypt(before), 0, "before the takeover", c.alice, false)

	// 2. Bob2 has no leaf, declares rotate, and the server accepts it.
	bob2 := newTakeoverKeeper(t, c.bob, e2eDevice2)
	oldBob, _, err := keychain.GetMLSLeafNewest(c.alice.store, c.alice.id, c.bob.id)
	if err != nil {
		t.Fatal(err)
	}
	decl := bob2.declare(proto.MLSLeafReasonRotate, oldBob.NotBefore+60)
	if decl.Reason != proto.MLSLeafReasonRotate || decl.SignatureKeyFingerprint == oldBob.Fingerprint {
		t.Fatalf("bob2's takeover declaration = %+v", decl)
	}
	takeover := proto.ChatStateLeafReplacement{AccountID: c.bob.id, NewSignatureKeyFP: decl.SignatureKeyFingerprint}

	// 3. The permit lists Bob → Bob2's key. Alice is latched, and the refusal
	// leaves her group state exactly as it was. Bob's old device is latched
	// on the same list: its own leaf is the one being replaced.
	c.alice.replacing = []proto.ChatStateLeafReplacement{takeover}
	c.bob.replacing = c.alice.replacing
	bob2.replacing = c.alice.replacing
	assertReplacementLatch(t, c.alice, takeover)
	state := c.alice.storedGroupState()
	c.alice.refused(proto.MLSEncrypt, c.alice.encryptRequest(messageID(2), 1, "to the old leaf"),
		proto.ChatMLSErrorCodeLeafReplacementPending)
	if !bytes.Equal(state, c.alice.storedGroupState()) {
		t.Fatal("a refused send changed alice's group state")
	}
	c.bob.refused(proto.MLSEncrypt, c.bob.encryptRequest(messageID(3), 1, "from the old device"),
		proto.ChatMLSErrorCodeLeafReplacementPending)

	// The server dropping the entry is not a reason to resume: the old leaf
	// is still in Alice's confirmed group.
	c.alice.replacing = nil
	c.alice.refused(proto.MLSEncrypt, c.alice.encryptRequest(messageID(2), 1, "to the old leaf"),
		proto.ChatMLSErrorCodeLeafReplacementPending)
	assertReplacementLatch(t, c.alice, takeover)
	c.alice.replacing = []proto.ChatStateLeafReplacement{takeover}

	// A replace carrying a KeyPackage of any other key than the listed one is
	// refused and persists nothing. Bob's old device's KeyPackage is exactly
	// that case: the right account, the wrong key.
	resp := c.alice.buildReplace(1, replaceOf(c.bob.keyPackage()))
	if resp.Success || string(resp.ErrorCode) != proto.ChatMLSErrorCodeLeafUntrusted {
		t.Fatalf("replace with the old leaf's key package = %+v; want %s", resp, proto.ChatMLSErrorCodeLeafUntrusted)
	}
	if got := c.alice.status(); got.CommitPending || got.Epoch != 1 {
		t.Fatalf("a refused replace left %+v", got)
	}
	if !bytes.Equal(state, c.alice.storedGroupState()) {
		t.Fatal("a refused replace changed alice's group state")
	}

	// 4. Alice replaces Bob's leaf with Bob2's; the server accepts it.
	bob2KP := bob2.keyPackage()
	built := commitOf(c.alice.must(proto.MLSCommitBuild, proto.MLSCommitBuildRequest{
		Permit: c.alice.permit(), OrgID: e2eOrg, ConversationID: e2eConv,
		ClientCommitID: c.alice.nextCommitID(), ExpectedEpoch: 1, Replace: []proto.MLSReplaceMember{replaceOf(bob2KP)},
	}))
	if built.WelcomeB64 == "" || built.WelcomeReleasable {
		t.Fatalf("replace commit = %+v", built)
	}
	// Pending is not confirmed: the latch still holds, and nothing is sent.
	assertReplacementLatch(t, c.alice, takeover)
	c.alice.refused(proto.MLSEncrypt, c.alice.encryptRequest(messageID(2), 1, "x"), proto.ChatMLSErrorCodeCommitPending)

	confirmed := c.alice.confirm(built.ClientCommitID, proto.MLSCommitOutcomeAccepted, "")
	if confirmed.Epoch != 2 || !confirmed.WelcomeReleasable {
		t.Fatalf("confirm = %+v", confirmed)
	}
	assertReplacementLatch(t, c.alice)

	// 5. Bob2 joins from the Welcome, and messages cross both ways with the
	// sender named from the credential.
	joined := bob2.must(proto.MLSJoin, proto.MLSJoinRequest{
		Permit: bob2.permit(), OrgID: e2eOrg, ConversationID: e2eConv, WelcomeB64: built.WelcomeB64,
	}).Data.(proto.MLSJoinResponseData)
	if joined.Epoch != 2 {
		t.Fatalf("bob2 joined at epoch %d, want 2", joined.Epoch)
	}
	assertReplacementLatch(t, bob2)

	toBob2 := c.send(c.alice, 4, 2, "welcome back")
	assertShown(t, bob2.decrypt(toBob2), 0, "welcome back", c.alice, false)
	fromBob2 := c.send(bob2, 5, 2, "new laptop")
	got := c.alice.decrypt(fromBob2)
	if plaintextOf(t, got.PlaintextB64[0]) != "new laptop" ||
		got.Items[0].SenderAccountID != c.bob.id || got.Items[0].SenderDeviceID != e2eDevice2 {
		t.Fatalf("alice read %q from %+v; want bob's new device", plaintextOf(t, got.PlaintextB64[0]), got.Items[0])
	}

	// 6. Bob's old device applies the Commit and learns it was removed.
	if got := c.bob.process(c.nextSeq(), 2, built.CommitB64); !got.Removed {
		t.Fatalf("bob's old device processed the replace as %+v", got)
	}
	// It cannot read the new epoch.
	resp = c.bob.call(proto.MLSDecryptBatchForAppDisplay, c.bob.decryptRequest(toBob2))
	if resp.Success {
		t.Fatal("the removed device read a message of the epoch it was removed from")
	}
}

// A replace for an account the permit does not list, and one mixed with
// another kind, are refused at the edge before anything is opened.
func TestMLSChatE2E_AReplaceThePermitDoesNotCoverIsRefused(t *testing.T) {
	c := newDM(t)
	bob2 := newTakeoverKeeper(t, c.bob, e2eDevice2)
	oldBob, _, _ := keychain.GetMLSLeafNewest(c.alice.store, c.alice.id, c.bob.id)
	decl := bob2.declare(proto.MLSLeafReasonRotate, oldBob.NotBefore+60)
	kp := bob2.keyPackage()

	resp := c.alice.buildReplace(1, replaceOf(kp))
	if resp.Success || string(resp.ErrorCode) != proto.ChatStateErrorCodeInvalidInput {
		t.Fatalf("replace of an unlisted account = %+v", resp)
	}

	c.alice.replacing = []proto.ChatStateLeafReplacement{{AccountID: c.bob.id, NewSignatureKeyFP: decl.SignatureKeyFingerprint}}
	c.alice.refused(proto.MLSCommitBuild, proto.MLSCommitBuildRequest{
		Permit: c.alice.permit(), OrgID: e2eOrg, ConversationID: e2eConv,
		ClientCommitID: c.alice.nextCommitID(), ExpectedEpoch: 1,
		Replace: []proto.MLSReplaceMember{replaceOf(kp)}, UpdateSelf: true,
	}, proto.ChatStateErrorCodeInvalidInput)

	// A KeyPackage of another account named as Bob's replacement is refused
	// by the credential check.
	other := proto.MLSReplaceMember{AccountID: c.bob.id, KeyPackageB64: c.alice.keyPackage().KeyPackageB64}
	c.alice.refused(proto.MLSCommitBuild, proto.MLSCommitBuildRequest{
		Permit: c.alice.permit(), OrgID: e2eOrg, ConversationID: e2eConv,
		ClientCommitID: c.alice.nextCommitID(), ExpectedEpoch: 1, Replace: []proto.MLSReplaceMember{other},
	}, proto.ChatMLSErrorCodeLeafUntrusted)
	if got := c.alice.status(); got.CommitPending || got.Epoch != 1 {
		t.Fatalf("refused replaces left %+v", got)
	}
}

// Double takeover: Bob2 takes over, then Bob3 takes over before any replace
// lands. Alice's latch moves to Bob3's key without lifting, a replace with
// Bob2's KeyPackage under the new permit is refused and writes nothing, and
// the replace with Bob3's lifts it.
func TestMLSChatE2E_ADoubleTakeoverWaitsForTheLatestDevice(t *testing.T) {
	c := newDM(t)
	oldBob, _, err := keychain.GetMLSLeafNewest(c.alice.store, c.alice.id, c.bob.id)
	if err != nil {
		t.Fatal(err)
	}
	bob2 := newTakeoverKeeper(t, c.bob, e2eDevice2)
	decl2 := bob2.declare(proto.MLSLeafReasonRotate, oldBob.NotBefore+60)
	bob2KP := bob2.keyPackage()
	c.alice.replacing = []proto.ChatStateLeafReplacement{{AccountID: c.bob.id, NewSignatureKeyFP: decl2.SignatureKeyFingerprint}}
	c.alice.refused(proto.MLSEncrypt, c.alice.encryptRequest(messageID(1), 1, "x"),
		proto.ChatMLSErrorCodeLeafReplacementPending)

	bob3 := newTakeoverKeeper(t, c.bob, "d3333333-3333-4333-8333-333333333333")
	decl3 := bob3.declare(proto.MLSLeafReasonRotate, oldBob.NotBefore+120)
	third := proto.ChatStateLeafReplacement{AccountID: c.bob.id, NewSignatureKeyFP: decl3.SignatureKeyFingerprint}
	c.alice.replacing = []proto.ChatStateLeafReplacement{third}
	bob3.replacing = c.alice.replacing
	assertReplacementLatch(t, c.alice, third)

	state := c.alice.storedGroupState()
	resp := c.alice.buildReplace(1, replaceOf(bob2KP))
	if resp.Success || string(resp.ErrorCode) != proto.ChatMLSErrorCodeLeafUntrusted {
		t.Fatalf("replace with bob2 under the bob3 permit = %+v", resp)
	}
	if got := c.alice.status(); got.CommitPending || got.Epoch != 1 || !bytes.Equal(state, c.alice.storedGroupState()) {
		t.Fatalf("the refused replace left %+v", got)
	}

	built := commitOf(c.alice.must(proto.MLSCommitBuild, proto.MLSCommitBuildRequest{
		Permit: c.alice.permit(), OrgID: e2eOrg, ConversationID: e2eConv,
		ClientCommitID: c.alice.nextCommitID(), ExpectedEpoch: 1,
		Replace: []proto.MLSReplaceMember{replaceOf(bob3.keyPackage())},
	}))
	c.alice.confirm(built.ClientCommitID, proto.MLSCommitOutcomeAccepted, "")
	assertReplacementLatch(t, c.alice)
	bob3.must(proto.MLSJoin, proto.MLSJoinRequest{
		Permit: bob3.permit(), OrgID: e2eOrg, ConversationID: e2eConv, WelcomeB64: built.WelcomeB64,
	})
	assertShown(t, bob3.decrypt(c.send(c.alice, 2, 2, "third time")), 0, "third time", c.alice, false)
}

// takeOver runs the M4.4 takeover of Bob's account by to, from the rotate
// through Alice's accepted replace, to's join and from's removal, and leaves
// the server as it is once the replace landed: the pending replacement row is
// gone, so no permit lists it any more. It returns the new epoch.
func (c *dm) takeOver(from, to *keeper, epoch uint64, notBefore int64) uint64 {
	c.alice.t.Helper()
	decl := to.declare(proto.MLSLeafReasonRotate, notBefore)
	listed := []proto.ChatStateLeafReplacement{{AccountID: c.bob.id, NewSignatureKeyFP: decl.SignatureKeyFingerprint}}
	c.alice.replacing, from.replacing, to.replacing = listed, listed, listed
	// The old device is still in use, and the send it tries now is refused.
	// The refusal stores the latch in its record, waiting for to's key.
	from.refused(proto.MLSEncrypt, from.encryptRequest(messageID(int(epoch)*100), epoch, "still here"),
		proto.ChatMLSErrorCodeLeafReplacementPending)

	built := commitOf(c.alice.must(proto.MLSCommitBuild, proto.MLSCommitBuildRequest{
		Permit: c.alice.permit(), OrgID: e2eOrg, ConversationID: e2eConv,
		ClientCommitID: c.alice.nextCommitID(), ExpectedEpoch: epoch,
		Replace: []proto.MLSReplaceMember{replaceOf(to.keyPackage())},
	}))
	c.alice.confirm(built.ClientCommitID, proto.MLSCommitOutcomeAccepted, "")
	c.alice.replacing, from.replacing, to.replacing = nil, nil, nil

	joined := to.must(proto.MLSJoin, proto.MLSJoinRequest{
		Permit: to.permit(), OrgID: e2eOrg, ConversationID: e2eConv, WelcomeB64: built.WelcomeB64,
	}).Data.(proto.MLSJoinResponseData)
	if joined.Epoch != epoch+1 {
		c.alice.t.Fatalf("%s joined at epoch %d, want %d", to.device[:8], joined.Epoch, epoch+1)
	}
	if got := from.process(c.nextSeq(), epoch+1, built.CommitB64); !got.Removed {
		c.alice.t.Fatalf("%s processed the replace as %+v", from.device[:8], got)
	}
	return epoch + 1
}

func (k *keeper) forgetRemoved() proto.MLSConversationForgetRemovedResponseData {
	k.t.Helper()
	return k.must(proto.MLSConversationForgetRemoved, proto.MLSConversationForgetRemovedRequest{
		Permit: k.permit(), OrgID: e2eOrg, ConversationID: e2eConv,
	}).Data.(proto.MLSConversationForgetRemovedResponseData)
}

func (k *keeper) refuseForget() {
	k.t.Helper()
	k.refused(proto.MLSConversationForgetRemoved, proto.MLSConversationForgetRemovedRequest{
		Permit: k.permit(), OrgID: e2eOrg, ConversationID: e2eConv,
	}, proto.ChatStateErrorCodeConflict)
}

// The reproduction: the user switches back to the old device after a
// takeover, Bob → Bob2 → Bob, without forgetting the removed group first. The
// join succeeds, because the removed group was left at the epoch before the
// replace and the Welcome is past it. But the record still carries the latch
// that waits for Bob2's key, no permit lists the takeover any more, and every
// send in the new group is refused with nothing able to lift it.
func TestMLSChatE2E_ASwitchBackWithoutForgettingStaysLatched(t *testing.T) {
	c := newDM(t)
	oldBob, _, err := keychain.GetMLSLeafNewest(c.alice.store, c.alice.id, c.bob.id)
	if err != nil {
		t.Fatal(err)
	}
	bob2 := newTakeoverKeeper(t, c.bob, e2eDevice2)
	epoch := c.takeOver(c.bob, bob2, 1, oldBob.NotBefore+60)
	epoch = c.takeOver(bob2, c.bob, epoch, oldBob.NotBefore+120)

	c.bob.refused(proto.MLSEncrypt, c.bob.encryptRequest(messageID(1), epoch, "back on the old laptop"),
		proto.ChatMLSErrorCodeLeafReplacementPending)
	// The join replaced the removed group, so the record is no longer one
	// this device was removed from and it cannot be forgotten any more: the
	// app has to forget before it joins.
	c.bob.refuseForget()
}

// The whole round trip with the removed group forgotten before the switch
// back: Bob → Bob2 → Bob, Bob added again and joined from the new Welcome.
func TestMLSChatE2E_TheOldDeviceSwitchesBackAndRejoins(t *testing.T) {
	c := newDM(t)
	before := c.send(c.alice, 1, 1, "before the takeover")
	assertShown(t, c.bob.decrypt(before), 0, "before the takeover", c.alice, false)
	oldBob, _, err := keychain.GetMLSLeafNewest(c.alice.store, c.alice.id, c.bob.id)
	if err != nil {
		t.Fatal(err)
	}
	bob2 := newTakeoverKeeper(t, c.bob, e2eDevice2)
	epoch := c.takeOver(c.bob, bob2, 1, oldBob.NotBefore+60)

	// Only the removed device may forget, and only its own removed group.
	c.alice.refuseForget()
	bob2.refuseForget()
	if got := c.bob.forgetRemoved(); !got.Forgotten {
		t.Fatalf("forget = %+v", got)
	}
	if again := c.bob.forgetRemoved(); again.Forgotten {
		t.Fatalf("forget again = %+v; want nothing to forget", again)
	}
	if got := c.bob.status(); got.HasGroupState || got.CommitPending || got.NeedsRekey || len(got.LeafReplacementLatch) != 0 {
		t.Fatalf("bob's status after the forget = %+v", got)
	}
	// What the old device had read stays readable.
	assertShown(t, c.bob.decrypt(before), 0, "before the takeover", c.alice, true)

	epoch = c.takeOver(bob2, c.bob, epoch, oldBob.NotBefore+120)
	assertReplacementLatch(t, c.bob)
	fromBob := c.send(c.bob, 2, epoch, "back on the old laptop")
	assertShown(t, c.alice.decrypt(fromBob), 0, "back on the old laptop", c.bob, false)
	toBob := c.send(c.alice, 3, epoch, "welcome back again")
	assertShown(t, c.bob.decrypt(toBob), 0, "welcome back again", c.alice, false)
	assertShown(t, c.bob.decrypt(before), 0, "before the takeover", c.alice, true)
}
