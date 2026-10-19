//go:build keeper_e2e

package dispatch

import (
	"github.com/dragpass/keeper/internal/keystore/handlers"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// e2eActions are test-only actions, registered only in a keeper_e2e build.
func e2eActions() map[string]action {
	return map[string]action{
		// Query the SHA-256 hash recorded in MemoryClipboard under
		// KEEPER_E2E_MODE.
		proto.ActionClipboardGetLastHash: wrap(handlers.HandleClipboardGetLastHash),
	}
}
