//go:build mls && cgo

package mls_test

import (
	"testing"

	"github.com/dragpass/keeper/internal/keystore/chatstate"
	"github.com/dragpass/keeper/internal/keystore/mls"
)

func TestTheStoredGroupStateStopsGrowingAfterSixteenPriorEpochs(t *testing.T) {
	g := newGroup(t)
	const settle, epochs = 20, 40
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
