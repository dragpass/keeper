// registry_peer_key.go — peer account key pin action registrations.
//
// Mirrors proto/actions_peer_key.go. These nine go through wrap() like most
// actions: none of them is bound into a server signature, so the lenient
// decode is fine and the strict decoder the message and chat actions need
// would buy nothing here.
//
// peer_key_chain_evaluate is the exception on size: it carries a rotation
// chain like the wrap actions do, so it takes the same payload ceiling, and
// the refusal lands before the decode rather than after.

package dispatch

import (
	"github.com/dragpass/keeper/internal/keystore/handlers"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

func peerKeyActions() map[string]action {
	return map[string]action{
		proto.ActionKeyTransparencyStatus: wrap(handlers.HandleKeyTransparencyStatus),
		// The key-trust screens are the App's: list, verify, the safety
		// number and the chain evaluation have no Extension caller. pin_get
		// and the policy stay for the Extension's wrap callers and options.
		proto.ActionPeerKeyPinList:   wrap(handlers.HandlePeerKeyPinList).appOnlyAction(),
		proto.ActionPeerKeyPinGet:    wrap(handlers.HandlePeerKeyPinGet),
		proto.ActionPeerKeyPinVerify: wrap(handlers.HandlePeerKeyPinVerify).appOnlyAction(),
		proto.ActionPeerKeyPinForget: wrap(handlers.HandlePeerKeyPinForget),
		// the pairwise safety number (design Q10)
		proto.ActionPeerKeySafetyNumber: wrap(handlers.HandlePeerKeySafetyNumber).appOnlyAction(),
		proto.ActionPeerKeyChainEvaluate: wrapCapped(
			proto.DEKRewrapMaxRequestBytes, handlers.HandlePeerKeyChainEvaluate,
		).appOnlyAction(),
		proto.ActionPeerKeyOwnerReset: wrap(handlers.HandlePeerKeyOwnerReset),
		proto.ActionPeerKeyPolicyGet:  wrap(handlers.HandlePeerKeyPolicyGet),
		proto.ActionPeerKeyPolicySet:  wrap(handlers.HandlePeerKeyPolicySet),
	}
}
