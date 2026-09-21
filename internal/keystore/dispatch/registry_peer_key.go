// registry_peer_key.go — peer account key pin action registrations.
//
// Mirrors proto/actions_peer_key.go. These six go through wrap() like most
// actions: none of them is bound into a server signature, so the lenient
// decode is fine and the strict decoder the message and chat actions need
// would buy nothing here.

package dispatch

import (
	"github.com/dragpass/keeper/internal/keystore/handlers"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

func peerKeyActions() map[string]actionHandlerFunc {
	return map[string]actionHandlerFunc{
		proto.ActionPeerKeyPinList:   wrap(handlers.HandlePeerKeyPinList),
		proto.ActionPeerKeyPinGet:    wrap(handlers.HandlePeerKeyPinGet),
		proto.ActionPeerKeyPinVerify: wrap(handlers.HandlePeerKeyPinVerify),
		proto.ActionPeerKeyPinForget: wrap(handlers.HandlePeerKeyPinForget),
		proto.ActionPeerKeyPolicyGet: wrap(handlers.HandlePeerKeyPolicyGet),
		proto.ActionPeerKeyPolicySet: wrap(handlers.HandlePeerKeyPolicySet),
	}
}
