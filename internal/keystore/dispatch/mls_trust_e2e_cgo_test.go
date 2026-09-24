//go:build mls && cgo

package dispatch

import (
	"slices"
	"strings"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

func assertTrust(t *testing.T, what string, got []proto.MLSAccountTrust, want ...proto.MLSAccountTrust) {
	t.Helper()
	if !slices.Equal(got, want) {
		t.Fatalf("%s trust = %+v; want %+v", what, got, want)
	}
}

func trustOf(accountID string, state keychain.PeerKeyPinState) proto.MLSAccountTrust {
	return proto.MLSAccountTrust{AccountID: accountID, State: string(state)}
}

// The responses that bring leaves in say how the Keeper judged each account
// they carried, and a status read judges every account in the confirmed tree
// against the pin as it now stands. This account's own leaves are never
// listed, and an account the Keeper holds no pin for is left out rather than
// reported as a first use.
func TestMLSChatE2E_TrustStateComesFromTheKeeperThatJudgedTheLeaf(t *testing.T) {
	e2eStateRoot(t)
	alice, bob := newKeeper(t, e2eAlice), newKeeper(t, e2eBob)
	created := commitOf(alice.must(proto.MLSGroupCreate, proto.MLSGroupCreateRequest{
		Permit: alice.permit(), OrgID: e2eOrg, ConversationID: e2eConv,
		ClientCommitID: alice.nextCommitID(), Members: []proto.MLSMemberKeyPackage{bob.keyPackage()},
	}))
	assertTrust(t, "group create", created.LeafTrust, trustOf(e2eBob, keychain.PeerKeyPinStateTOFU))
	alice.confirm(created.ClientCommitID, proto.MLSCommitOutcomeAccepted, "")
	joined := bob.must(proto.MLSJoin, proto.MLSJoinRequest{
		Permit: bob.permit(), OrgID: e2eOrg, ConversationID: e2eConv, WelcomeB64: created.WelcomeB64,
	}).Data.(proto.MLSJoinResponseData)
	assertTrust(t, "join", joined.LeafTrust, trustOf(e2eAlice, keychain.PeerKeyPinStateTOFU))
	assertTrust(t, "status after join", bob.status().MemberTrust, trustOf(e2eAlice, keychain.PeerKeyPinStateTOFU))

	// Carol enters through Alice's Add; Bob, who applies it, reports her.
	carol := newKeeper(t, e2eCarol)
	add := commitOf(alice.must(proto.MLSCommitBuild, proto.MLSCommitBuildRequest{
		Permit: alice.permit(), OrgID: e2eOrg, ConversationID: e2eConv,
		ClientCommitID: alice.nextCommitID(), ExpectedEpoch: 1,
		Add: []proto.MLSMemberKeyPackage{carol.keyPackage()}, UserInitiated: true,
	}))
	assertTrust(t, "add", add.LeafTrust, trustOf(e2eCarol, keychain.PeerKeyPinStateTOFU))
	alice.confirm(add.ClientCommitID, proto.MLSCommitOutcomeAccepted, "")
	processed := bob.process(2, 2, add.CommitB64)
	assertTrust(t, "process", processed.LeafTrust, trustOf(e2eCarol, keychain.PeerKeyPinStateTOFU))

	// An Update brings in no account and reports none.
	update := alice.buildUpdate(2)
	assertTrust(t, "update", update.LeafTrust)
	alice.confirm(update.ClientCommitID, proto.MLSCommitOutcomeAccepted, "")
	assertTrust(t, "process of an update", bob.process(3, 3, update.CommitB64).LeafTrust)

	// The status follows the pin: verified, a pin moved past this leaf's key
	// by a rotation chain, and a pin for another key nothing explains.
	pin, err := keychain.GetPeerKeyPin(bob.store, bob.id, e2eAlice)
	if err != nil {
		t.Fatal(err)
	}
	observed := pin.Fingerprint
	setPin := func(p keychain.PeerKeyPin) {
		t.Helper()
		if err := keychain.SavePeerKeyPin(bob.store, bob.id, e2eAlice, p); err != nil {
			t.Fatal(err)
		}
	}
	verified := pin
	verified.State, verified.VerifiedAt = keychain.PeerKeyPinStateVerified, pin.FirstSeenAt
	setPin(verified)
	carolTOFU := trustOf(e2eCarol, keychain.PeerKeyPinStateTOFU)
	assertTrust(t, "status, verified", bob.status().MemberTrust, trustOf(e2eAlice, keychain.PeerKeyPinStateVerified), carolTOFU)

	moved := pin
	moved.Fingerprint = strings.Repeat("0", len(observed))
	moved.State, moved.LastRotationFingerprint = keychain.PeerKeyPinStateVerified, observed
	setPin(moved)
	assertTrust(t, "status, rotated past", bob.status().MemberTrust, trustOf(e2eAlice, keychain.PeerKeyPinStateRotated), carolTOFU)

	moved.LastRotationFingerprint = ""
	setPin(moved)
	assertTrust(t, "status, unexplained", bob.status().MemberTrust, trustOf(e2eAlice, keychain.PeerKeyPinStateChanged), carolTOFU)

	if _, err := keychain.DeletePeerKeyPin(bob.store, bob.id, e2eAlice); err != nil {
		t.Fatal(err)
	}
	assertTrust(t, "status, no pin", bob.status().MemberTrust, carolTOFU)
}
