//go:build !keeper_e2e

package dispatch

import (
	"testing"

	"github.com/dragpass/keeper/internal/keystore/proto"
)

// A Group DEK wrapped to a caller's key opens bound tokens offline, so the
// three wrap actions run only for the paired App (protocol.md "Group DEK
// rewrap targets"). A release build refuses them to every Native Messaging
// frame.
func TestGroupDEKWrapActionsAreAppOnlyInRelease(t *testing.T) {
	for _, name := range []string{
		proto.ActionGroupRewrapPrepare,
		proto.ActionGroupDEKGenerateAndOpen,
		proto.ActionDEKRewrapForMember,
		proto.ActionDEKUnwrapAndRewrapForMany,
	} {
		entry, ok := actionRegistry[name]
		if !ok || !entry.appOnly || entry.mcp || entry.plaintext {
			t.Fatalf("%s must be App-only without plaintext output", name)
		}
		if !AppOnly(name) {
			t.Fatalf("%s must be refused to Native Messaging in a release build", name)
		}
	}
}
