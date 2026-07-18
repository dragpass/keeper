// registry_core.go — core / uncategorized action registrations.
//
// Mirrors proto/actions.go: the health-check ping and the test-only clipboard
// hash query, neither of which belongs to a specific domain.

package dispatch

import (
	"github.com/dragpass/keeper/internal/keystore/handlers"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

func coreActions() map[string]actionHandlerFunc {
	return map[string]actionHandlerFunc{
		proto.ActionPing:                     wrap(handlers.HandlePing),
		proto.ActionUserPresenceCapabilities: wrap(handlers.HandleUserPresenceCapabilities),

		// test-only — query SHA-256 hash recorded in MemoryClipboard under
		// KEEPER_E2E_MODE.
		proto.ActionClipboardGetLastHash: wrap(handlers.HandleClipboardGetLastHash),
	}
}
