// registry_core.go — core / uncategorized action registrations.
//
// Mirrors proto/actions.go: the health-check ping, which belongs to no
// specific domain. The test-only clipboard hash query is in registry_e2e.go.

package dispatch

import (
	"github.com/dragpass/keeper/internal/keystore/handlers"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

func coreActions() map[string]action {
	return map[string]action{
		proto.ActionPing: wrap(handlers.HandlePing).onMCP(),
	}
}
