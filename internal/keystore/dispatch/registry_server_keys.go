// registry_server_keys.go — server-key trust anchor action registrations.
//
// Mirrors proto/actions_server_keys.go: the server public-key trust anchor and
// the multi-version server-key refresh.

package dispatch

import (
	"github.com/dragpass/keeper/internal/keystore/handlers"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

func serverKeyActions() map[string]actionHandlerFunc {
	return map[string]actionHandlerFunc{
		proto.ActionGetServerPublicKey: wrap(handlers.HandleGetServerPublicKey),

		// multi-version server public key refresh
		proto.ActionRefreshServerKeys: wrap(handlers.HandleRefreshServerKeys),
	}
}
