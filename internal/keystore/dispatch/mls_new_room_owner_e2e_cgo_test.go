//go:build mls && cgo

// A new room's creator is its owner, in the authenticated group context from
// its first epoch (N11). The server's my_role is never read for it, and
// nothing about another room carries over.

package dispatch

import (
	"testing"

	"github.com/dragpass/keeper/internal/keystore/chatstate"
	"github.com/dragpass/keeper/internal/keystore/mls/mlsadversary"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

func TestMLSNewRoom_ACreateThatNamesAnotherOwnerIsRefused(t *testing.T) {
	e2eStateRoot(t)
	alice, bob := newKeeper(t, e2eAlice), newKeeper(t, e2eBob)
	resp := alice.call(proto.MLSGroupCreate, proto.MLSGroupCreateRequest{
		Permit: alice.permit(), OrgID: e2eOrg, ConversationID: e2eConv, ClientCommitID: alice.nextCommitID(),
		Members: []proto.MLSMemberKeyPackage{bob.keyPackage()},
		Roles:   roleSet(e2eBob, e2eAlice),
	})
	assertCode(t, resp, proto.ChatStateErrorCodeInvalidInput)
	if got := alice.status(); got.HasGroupState || got.CommitPending {
		t.Fatalf("a refused create left %+v", got)
	}
}

// A modified client creates a room whose first roles name somebody else as
// owner. Carol refuses to join from its Welcome; the same client's room that
// names itself is joined.
func TestMLSNewRoom_AWelcomeWhoseFirstRolesNameAnotherOwnerIsRefused(t *testing.T) {
	for _, honest := range []bool{false, true} {
		e2eStateRoot(t)
		carol, mallory := newKeeper(t, e2eCarol), newKeeper(t, advMallory)
		adv := mlsadversary.Start(t, leafKeyOf(t, mallory), true)
		owner := e2eCarol
		if honest {
			owner = advMallory
		}
		roles := chatstate.Roles{Kind: chatstate.RolesKindRoom, Owner: owner}
		adv.Create([]byte(e2eConv), roles.Encode())
		_, welcome := adv.Build(mlsadversary.Commit{Adds: [][]byte{keyPackageBytes(t, carol.keyPackage())}, Apply: true})
		resp := carol.call(proto.MLSJoin, proto.MLSJoinRequest{
			Permit: carol.permit(), OrgID: e2eOrg, ConversationID: e2eConv, WelcomeB64: advB64(welcome),
		})
		if honest {
			if !resp.Success {
				t.Fatalf("carol refused the honest room: %+v", resp)
			}
			continue
		}
		assertCode(t, resp, proto.ChatMLSErrorCodeFailed)
		if got := carol.status(); got.HasGroupState {
			t.Fatalf("carol joined a room whose first roles name her owner: %+v", got)
		}
	}
}
