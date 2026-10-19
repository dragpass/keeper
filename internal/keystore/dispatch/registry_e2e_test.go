//go:build keeper_e2e

package dispatch

import (
	"testing"

	"github.com/dragpass/keeper/internal/keystore/proto"
)

func TestE2ERegistryHasTheClipboardHashQuery(t *testing.T) {
	if _, ok := actionRegistry[proto.ActionClipboardGetLastHash]; !ok {
		t.Fatalf("a keeper_e2e build must register %s", proto.ActionClipboardGetLastHash)
	}
}
