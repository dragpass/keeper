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

// The E2E binary serves the Group DEK wrap actions to the Extension's
// organization fixtures over Native Messaging and nothing else App-only.
func TestE2EBuildServesOnlyTheGroupDEKWrapFixturesOverNative(t *testing.T) {
	fixtures := map[string]bool{
		proto.ActionGroupDEKGenerateAndOpen:   true,
		proto.ActionDEKRewrapForMember:        true,
		proto.ActionDEKUnwrapAndRewrapForMany: true,
	}
	for name, entry := range actionRegistry {
		if !entry.appOnly {
			continue
		}
		if AppOnly(name) == fixtures[name] {
			t.Fatalf("%s: refused to Native Messaging = %t in a keeper_e2e build", name, AppOnly(name))
		}
	}
	for name := range fixtures {
		if !actionRegistry[name].appOnly {
			t.Fatalf("%s must stay App-only in the registry", name)
		}
	}
}
