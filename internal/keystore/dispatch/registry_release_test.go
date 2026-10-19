//go:build !keeper_e2e

package dispatch

import (
	"testing"

	"github.com/dragpass/keeper/internal/keystore/proto"
)

func TestReleaseRegistryHasNoTestOnlyActions(t *testing.T) {
	if _, ok := actionRegistry[proto.ActionClipboardGetLastHash]; ok {
		t.Fatalf("%s is test-only and must not be registered without the keeper_e2e tag", proto.ActionClipboardGetLastHash)
	}
}
