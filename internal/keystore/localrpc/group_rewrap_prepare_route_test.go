package localrpc

import (
	"testing"

	"github.com/dragpass/keeper/internal/keystore/proto"
)

func TestGroupRewrapPrepareUsesPairedAppRoute(t *testing.T) {
	route, found := appRoutes["/v1/group-dek/rewrap-prepare"]
	if !found || route.action != proto.ActionGroupRewrapPrepare || route.input == nil {
		t.Fatal("Group rewrap preparation must use the paired App route")
	}
}

func TestQuorumCombineRoutePreservesDecisionAndSession(t *testing.T) {
	decision := &proto.GroupRewrapDecision{Operation: "quorum_combine"}
	input := &appQuorumCombine{OwnerAccountID: routeOwner, Recipients: []proto.DEKRewrapRecipient{{AccountID: routePeer}}, RecoverySessionID: "99999999-9999-4999-8999-999999999999", Decision: decision}
	bound, err := bindQuorumCombine(nil, input)
	if err != nil {
		t.Fatal(err)
	}
	request := bound.(proto.ArchiveQuorumCombineAndRewrapRequest)
	if request.RecoverySessionID != input.RecoverySessionID || request.Decision != decision {
		t.Fatal("route dropped combine authority")
	}
}
