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
