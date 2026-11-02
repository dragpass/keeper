// Entry value-change tracking registrations (lv83). Native Messaging only:
// the Extension seals drag tokens; the App and MCP do not.

package dispatch

import (
	"github.com/dragpass/keeper/internal/keystore/handlers"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

func changeTrackActions() map[string]action {
	return map[string]action{
		proto.ActionGroupEncryptBoundTracked: wrap(handlers.HandleGroupEncryptBoundTracked),
		// Baseline from an existing token: strict decoders, lv79 online decision.
		proto.ActionGroupChangeBaselinePrepare:      direct(handlers.HandleGroupChangeBaselinePrepare),
		proto.ActionGroupChangeBaselineExecute:      direct(handlers.HandleGroupChangeBaselineExecute),
		proto.ActionDEKUnwrapAndEncryptBoundTracked: wrap(handlers.HandleDEKUnwrapAndEncryptBoundTracked),
		// Comparison decision (lv83 H1): no verdict without it.
		proto.ActionGroupChangeComparePrepare: direct(handlers.HandleGroupChangeComparePrepare),
	}
}
