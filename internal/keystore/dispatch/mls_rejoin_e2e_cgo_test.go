//go:build mls && cgo

// A signed rejoin end to end (design Q6): a member whose Welcome it could not
// use signs a request to be re-seated, another member's Keeper verifies it
// against the KeyPackage it re-seats the account with and builds one Commit
// that removes the dead leaf and adds the new one, which every receiver
// accepts as the R2 shape.

package dispatch

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// deadLeafRoom is Alice and Carol at epoch 1 with a leaf of Bob's that nobody
// holds keys for: Alice added Bob, and Bob never joined from that Welcome.
func deadLeafRoom(t *testing.T) (alice, bob, carol *keeper) {
	t.Helper()
	e2eStateRoot(t)
	alice, bob, carol = newKeeper(t, e2eAlice), newKeeper(t, e2eBob), newKeeper(t, e2eCarol)
	id := alice.nextCommitID()
	created := commitOf(alice.must(proto.MLSGroupCreate, proto.MLSGroupCreateRequest{
		Permit: alice.permit(), OrgID: e2eOrg, ConversationID: e2eConv, ClientCommitID: id,
		Members: []proto.MLSMemberKeyPackage{bob.keyPackage(), carol.keyPackage()},
	}))
	alice.confirm(id, proto.MLSCommitOutcomeAccepted, "")
	carol.must(proto.MLSJoin, proto.MLSJoinRequest{
		Permit: carol.permit(), OrgID: e2eOrg, ConversationID: e2eConv, WelcomeB64: created.WelcomeB64,
	})
	return alice, bob, carol
}

func (k *keeper) rejoinRequest() proto.MLSRejoinStatement {
	k.t.Helper()
	return k.must(proto.MLSRejoinRequestSign, proto.MLSRejoinRequestSignRequest{
		Permit: k.permit(), OrgID: e2eOrg, ConversationID: e2eConv,
	}).Data.(proto.MLSRejoinRequestSignResponseData).Request
}

func (k *keeper) buildRejoin(expected uint64, members ...proto.MLSRejoinMember) proto.BaseResponse {
	k.t.Helper()
	return k.call(proto.MLSCommitBuild, proto.MLSCommitBuildRequest{
		Permit: k.permit(), OrgID: e2eOrg, ConversationID: e2eConv,
		ClientCommitID: k.nextCommitID(), ExpectedEpoch: expected, Rejoin: members,
	})
}

func TestMLSRejoin_ASignedRequestReSeatsTheAccountInOneCommit(t *testing.T) {
	alice, bob, carol := deadLeafRoom(t)
	request := bob.rejoinRequest()
	if request.AccountID != e2eBob || request.DeviceID != e2eDevice || request.ConversationID != e2eConv {
		t.Fatalf("signed request = %+v", request)
	}
	kp := bob.keyPackage()
	// Automation may carry it out: the authority is Bob's own signature and
	// his dead leaf in the authenticated tree.
	built := commitOf(mustSucceed(t, "rejoin", alice.buildRejoin(1, proto.MLSRejoinMember{
		AccountID: e2eBob, DeviceID: e2eDevice, KeyPackageB64: kp.KeyPackageB64, Request: request,
	})))
	if built.WelcomeB64 == "" {
		t.Fatal("a rejoin carried no Welcome")
	}
	alice.confirm(built.ClientCommitID, proto.MLSCommitOutcomeAccepted, "")

	// Carol takes it as the R2 shape, with or without the row's attestation.
	if got := carol.process(2, 2, built.CommitB64); got.Epoch != 2 {
		t.Fatalf("carol applied the rejoin at %+v", got)
	}
	joined := bob.must(proto.MLSJoin, proto.MLSJoinRequest{
		Permit: bob.permit(), OrgID: e2eOrg, ConversationID: e2eConv, WelcomeB64: built.WelcomeB64,
	}).Data.(proto.MLSJoinResponseData)
	if joined.Epoch != 2 {
		t.Fatalf("bob joined at epoch %d", joined.Epoch)
	}
	sent := bob.encrypt(messageID(1), 2, "back again")
	shown := carol.decrypt(proto.MLSDisplayMessage{Seq: 3, CiphertextB64: sent.CiphertextB64})
	if got := plaintextOf(t, shown.PlaintextB64[0]); got != "back again" {
		t.Fatalf("carol read %q", got)
	}
}

func TestMLSRejoin_AnUnsignedOrForeignRequestBuildsNothing(t *testing.T) {
	alice, bob, carol := deadLeafRoom(t)
	good := bob.rejoinRequest()
	kp := bob.keyPackage()
	member := func(r proto.MLSRejoinStatement) proto.MLSRejoinMember {
		return proto.MLSRejoinMember{AccountID: e2eBob, DeviceID: e2eDevice, KeyPackageB64: kp.KeyPackageB64, Request: r}
	}

	garbage := good
	garbage.Signature = base64.StdEncoding.EncodeToString([]byte("not a signature"))

	carolPEM, err := keychain.GetPrivateKey(carol.store)
	if err != nil {
		t.Fatal(err)
	}
	carolKey, err := crypto.ParsePrivateKey(carolPEM)
	if err != nil {
		t.Fatal(err)
	}
	forged := good
	sig, err := crypto.SignData(carolKey, proto.MLSRejoinStatementCanonical(forged))
	if err != nil {
		t.Fatal(err)
	}
	forged.Signature = base64.StdEncoding.EncodeToString(sig)

	stale := good
	stale.RequestedAt = time.Now().Unix() - proto.MLSRejoinStatementMaxAgeSeconds - 60

	otherKey := good
	otherKey.SignatureKeyFingerprint = "00" + good.SignatureKeyFingerprint[2:]

	for name, r := range map[string]proto.MLSRejoinStatement{
		"garbage signature":          garbage,
		"signed by another account":  forged,
		"too old (signature intact)": stale,
		"names another leaf key":     otherKey,
	} {
		resp := alice.buildRejoin(1, member(r))
		if resp.Success || string(resp.ErrorCode) != proto.ChatMLSErrorCodeRejoinUnverified {
			t.Fatalf("%s: rejoin = %+v; want %s", name, resp, proto.ChatMLSErrorCodeRejoinUnverified)
		}
	}
	wrongConv := good
	wrongConv.ConversationID = e2eOrg
	alice.refused(proto.MLSCommitBuild, proto.MLSCommitBuildRequest{
		Permit: alice.permit(), OrgID: e2eOrg, ConversationID: e2eConv,
		ClientCommitID: alice.nextCommitID(), ExpectedEpoch: 1, Rejoin: []proto.MLSRejoinMember{member(wrongConv)},
	}, proto.ChatStateErrorCodeInvalidInput)
	if got := alice.status(); got.CommitPending || got.Epoch != 1 {
		t.Fatalf("a refused rejoin moved alice: %+v", got)
	}

	// The old two-Commit shape is not a way around the signature: an
	// automated Remove of Bob's leaf alone is not authorized.
	resp := alice.buildRemove(1, e2eBob)
	if resp.Success || string(resp.ErrorCode) != proto.ChatMLSErrorCodeCommitUnauthorized {
		t.Fatalf("a bare remove ahead of a rejoin = %+v", resp)
	}
}

// The P1 repro: a server lists for rejoin an account it controls that has a
// valid KeyPackage and no leaf in the group. Even with that account's own
// signed request, the Keeper refuses to Add it: a rejoin re-seats a leaf the
// authenticated tree already holds, and nothing else.
func TestMLSRejoin_AnAccountWithNoLeafInTheGroupIsNeverAdded(t *testing.T) {
	alice, _, _ := deadLeafRoom(t)
	mallory := newKeeper(t, "e5555555-5555-4555-8555-555555555555")
	request := mallory.rejoinRequest()
	kp := mallory.keyPackage()
	resp := alice.buildRejoin(1, proto.MLSRejoinMember{
		AccountID: mallory.id, DeviceID: e2eDevice, KeyPackageB64: kp.KeyPackageB64, Request: request,
	})
	if resp.Success || string(resp.ErrorCode) != proto.ChatMLSErrorCodeCommitUnauthorized {
		t.Fatalf("a rejoin of an account outside the group = %+v", resp)
	}
	if got := alice.status(); got.CommitPending || got.Epoch != 1 {
		t.Fatalf("a refused rejoin moved alice: %+v", got)
	}
	// Nor as a plain Add from automation.
	add := alice.call(proto.MLSCommitBuild, proto.MLSCommitBuildRequest{
		Permit: alice.permit(), OrgID: e2eOrg, ConversationID: e2eConv,
		ClientCommitID: alice.nextCommitID(), ExpectedEpoch: 1,
		Add: []proto.MLSMemberKeyPackage{mallory.keyPackage()},
	})
	if add.Success || string(add.ErrorCode) != proto.ChatMLSErrorCodeCommitUnauthorized {
		t.Fatalf("an automated add of the listed account = %+v", add)
	}
}
