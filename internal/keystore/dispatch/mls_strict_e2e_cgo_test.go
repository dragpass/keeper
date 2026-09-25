//go:build mls && cgo

// Strict mode in chat (design Q8 (a) + (ii)): the device-local
// require_verified_peers toggle, which the wrap actions already honour, also
// governs this device's MLS operations. On, it refuses a local Add or Join of
// a leaf whose account key nobody here verified, and a send in a
// conversation that holds such a member, naming who. Reading stays open, and
// a Commit somebody else made is never refused: it is applied, and sending
// stays refused until that member is verified or removed.

package dispatch

import (
	"slices"
	"testing"

	"github.com/dragpass/keeper/config"
	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

const codePeerUnverified = "CHAT_MLS_PEER_UNVERIFIED"

func (k *keeper) strict(on bool) {
	k.t.Helper()
	k.must(proto.ActionPeerKeyPolicySet, proto.PeerKeyPolicySetRequest{RequireVerifiedPeers: &on})
}

// verifyPeer is a person on k comparing peer's key out of band and settling it.
func (k *keeper) verifyPeer(peer *keeper) {
	k.t.Helper()
	pem, err := keychain.GetPublicKey(peer.store)
	if err != nil {
		k.t.Fatal(err)
	}
	k.must(proto.ActionPeerKeyPinVerify, proto.PeerKeyPinVerifyRequest{
		OwnerAccountID: k.id, AccountID: peer.id,
		Fingerprint: crypto.AccountKeyFingerprint([]byte(pem)), PublicKey: pem,
	})
}

func unverifiedOf(t *testing.T, resp proto.BaseResponse) []string {
	t.Helper()
	if resp.Success || string(resp.ErrorCode) != codePeerUnverified {
		t.Fatalf("response = %+v; want %s", resp, codePeerUnverified)
	}
	data, ok := resp.Data.(proto.MLSPeerUnverifiedData)
	if !ok {
		t.Fatalf("the refusal carries %T, not who is unverified", resp.Data)
	}
	return data.UnverifiedAccountIDs
}

// Q8's repro. With strict on, Alice's Keeper sends to Bob, whose key nobody
// here compared, and adds Carol, whose key nobody here has ever seen.
func TestMLSStrict_AnUnverifiedMemberBlocksSendsAndLocalAdds(t *testing.T) {
	c := newDM(t)
	c.alice.strict(true)

	got := unverifiedOf(t, c.alice.call(proto.MLSEncrypt, c.alice.encryptRequest(messageID(1), 1, "hi")))
	if !slices.Equal(got, []string{e2eBob}) {
		t.Fatalf("unverified = %v; want bob", got)
	}
	if st := c.alice.status(); !st.RequireVerifiedPeers || !slices.Equal(st.UnverifiedAccountIDs, []string{e2eBob}) {
		t.Fatalf("status = %+v", st)
	}
	// Reading stays open.
	assertShown(t, c.alice.decrypt(c.send(c.bob, 2, 1, "from bob")), 0, "from bob", c.bob, false)

	carol := newKeeper(t, e2eCarol)
	add := c.alice.call(proto.MLSCommitBuild, proto.MLSCommitBuildRequest{
		Permit: c.alice.permit(), OrgID: e2eOrg, ConversationID: e2eConv,
		ClientCommitID: c.alice.nextCommitID(), ExpectedEpoch: 1,
		Add: []proto.MLSMemberKeyPackage{carol.keyPackage()}, UserInitiated: true,
	})
	if got := unverifiedOf(t, add); !slices.Equal(got, []string{e2eCarol}) {
		t.Fatalf("add unverified = %v; want carol", got)
	}
	if st := c.alice.status(); st.CommitPending {
		t.Fatal("a refused add left a pending Commit")
	}

	// Verifying Bob opens sending; strict off opens everything.
	c.alice.verifyPeer(c.bob)
	c.alice.encrypt(messageID(3), 1, "verified now")
	if st := c.alice.status(); len(st.UnverifiedAccountIDs) != 0 {
		t.Fatalf("status after verifying = %+v", st)
	}
	c.alice.strict(false)
	c.alice.encrypt(messageID(4), 1, "strict off")
}

// A Welcome whose tree holds an unverified member is refused under strict
// and joined once that member is verified: the refusal kept the pool entry.
func TestMLSStrict_AJoinWaitsForTheMembersToBeVerified(t *testing.T) {
	e2eStateRoot(t)
	alice, bob := newKeeper(t, e2eAlice), newKeeper(t, e2eBob)
	id := alice.nextCommitID()
	created := commitOf(alice.must(proto.MLSGroupCreate, proto.MLSGroupCreateRequest{
		Permit: alice.permit(), OrgID: e2eOrg, ConversationID: e2eConv,
		ClientCommitID: id, Members: []proto.MLSMemberKeyPackage{bob.keyPackage()},
	}))
	alice.confirm(id, proto.MLSCommitOutcomeAccepted, "")

	bob.strict(true)
	join := proto.MLSJoinRequest{Permit: bob.permit(), OrgID: e2eOrg, ConversationID: e2eConv, WelcomeB64: created.WelcomeB64}
	if got := unverifiedOf(t, bob.call(proto.MLSJoin, join)); !slices.Equal(got, []string{e2eAlice}) {
		t.Fatalf("join unverified = %v; want alice", got)
	}
	bob.verifyPeer(alice)
	bob.must(proto.MLSJoin, join)
}

// A Commit somebody else made is applied even when it brings in a member
// nobody here verified; this device then refuses to send until it does.
func TestMLSStrict_AnInboundAddIsAppliedAndThenLatchesSends(t *testing.T) {
	c := newDM(t)
	c.bob.verifyPeer(c.alice)
	c.bob.strict(true)
	c.bob.encrypt(messageID(1), 1, "all verified")

	carol := newKeeper(t, e2eCarol)
	add := commitOf(c.alice.must(proto.MLSCommitBuild, proto.MLSCommitBuildRequest{
		Permit: c.alice.permit(), OrgID: e2eOrg, ConversationID: e2eConv,
		ClientCommitID: c.alice.nextCommitID(), ExpectedEpoch: 1,
		Add: []proto.MLSMemberKeyPackage{carol.keyPackage()}, UserInitiated: true,
	}))
	c.alice.confirm(add.ClientCommitID, proto.MLSCommitOutcomeAccepted, "")
	if got := c.bob.process(c.nextSeq(), 2, add.CommitB64); got.Epoch != 2 {
		t.Fatalf("bob applied the add as %+v", got)
	}
	got := unverifiedOf(t, c.bob.call(proto.MLSEncrypt, c.bob.encryptRequest(messageID(2), 2, "x")))
	if !slices.Equal(got, []string{e2eCarol}) {
		t.Fatalf("unverified = %v; want carol", got)
	}
}

// An unreadable policy record fails closed: the send and the status refuse
// rather than fall back to the default, which is off.
func TestMLSStrict_AnUnreadablePolicyFailsClosed(t *testing.T) {
	c := newDM(t)
	if err := c.alice.store.Set(config.Service, config.PeerKeyPolicyAccount, "{not json"); err != nil {
		t.Fatal(err)
	}
	c.alice.refused(proto.MLSEncrypt, c.alice.encryptRequest(messageID(1), 1, "x"), "storage_failure")
	resp := c.alice.call(proto.MLSConversationStatus, proto.MLSConversationStatusRequest{
		Permit: c.alice.permit(), OrgID: e2eOrg, ConversationID: e2eConv,
	})
	if resp.Success {
		t.Fatalf("status under an unreadable policy = %+v", resp)
	}
}
