//go:build mls && cgo

package mls_test

import (
	"os"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/chatstate"
	"github.com/dragpass/keeper/internal/keystore/mls"
)

// Nothing trims the past epochs RecordStorage keeps (mls/src/storage.rs,
// write inserts every epoch record and nothing removes one), so the stored
// group state grows with every Commit, and every past epoch's secrets stay on
// disk for as long as the conversation does. This test states the property a
// retention bound would give: after the first few epochs the state stops
// growing. It fails today.
//
// TODO(epoch-retention): skipped until the number of past epochs to keep is
// decided. That value is a pending user policy (matrix bug 2, P5); do not pick
// one here. Set DRAGPASS_RUN_PENDING_POLICY_TESTS=1 to run it and see the
// growth.
func TestPendingPolicy_TheStoredGroupStateStopsGrowingAcrossEpochs(t *testing.T) {
	if os.Getenv("DRAGPASS_RUN_PENDING_POLICY_TESTS") == "" {
		t.Skip("TODO(epoch-retention): past-epoch retention bound is a pending user policy (matrix bug 2)")
	}
	g := newGroup(t)
	const settle, epochs = 5, 40
	var settled int
	for epoch := 1; epoch <= epochs; epoch++ {
		built, err := g.aliceStore.BeginCommit(conv, noWatermark,
			chatstate.BeginCommitRequest{ClientCommitID: nextCommitID()}, mls.NewCipher(g.aliceS, trustAll{}))
		if err != nil {
			t.Fatalf("update at epoch %d: %v", epoch-1, err)
		}
		g.confirm(t, built.ClientCommitID)
		if epoch == settle {
			settled = len(g.storedState(t))
		}
	}
	if grown := len(g.storedState(t)); grown > settled {
		t.Fatalf("the stored group state grew from %d bytes at epoch %d to %d bytes at epoch %d: "+
			"every past epoch is kept", settled, settle, grown, epochs)
	}
}
