package handlers

import (
	"testing"

	"github.com/dragpass/keeper/internal/keystore/chatstate"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

func TestMLSLeafHandover_TheWindowIsTheSameOnBothSides(t *testing.T) {
	if proto.MLSLeafHandoverMaxSeconds != chatstate.HandoverMaxSeconds {
		t.Fatalf("proto window %d != chatstate window %d", proto.MLSLeafHandoverMaxSeconds, chatstate.HandoverMaxSeconds)
	}
}
