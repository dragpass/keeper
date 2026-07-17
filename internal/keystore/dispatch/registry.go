// registry.go — assembles the dispatcher action registry from domain fragments.
//
// The action set is partitioned across registry_<domain>.go files, one per
// proto/actions_<domain>.go file, so the dispatch registry and the wire-
// protocol constant set stay in lockstep and can be diffed side by side. Each
// fragment file exposes a func returning its slice of the action→handler map;
// buildRegistry merges the fragments in proto order and panics on any duplicate
// action key. That guard is what the plain map literal gave for free once the
// entries are spread across files: a copy-paste that registers the same action
// in two domain files fails loudly at package init (and under
// TestActionRegistry_Count) instead of silently shadowing.

package dispatch

import (
	"encoding/json"

	"github.com/dragpass/keeper/internal/keystore/handlers"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// actionHandlerFunc is the unified signature for the dispatcher action map
// ("action registry" — Go pattern terminology, unrelated to the DragPass
// product DragLink inventory).
type actionHandlerFunc func(d handlers.Deps, payload json.RawMessage) proto.BaseResponse

// wrap adapts a typed handler (func(handlers.Deps, T) proto.BaseResponse) to
// actionHandlerFunc. process[T] handles JSON decoding and the Validate call,
// so wrap is a simple delegation.
func wrap[T any](handler func(handlers.Deps, T) proto.BaseResponse) actionHandlerFunc {
	return func(d handlers.Deps, payload json.RawMessage) proto.BaseResponse {
		return process(payload, func(req T) proto.BaseResponse {
			return handler(d, req)
		})
	}
}

// actionFragment returns one domain's slice of the action→handler map.
type actionFragment func() map[string]actionHandlerFunc

// actionFragments lists every domain fragment. Keep this order aligned with the
// proto/actions_*.go files.
var actionFragments = []actionFragment{
	coreActions,
	identityActions,
	serverKeyActions,
	groupActions,
	archiveActions,
	archiveQuorumActions,
}

// actionRegistry maps action strings to handler functions, assembled from the
// domain fragments at package init.
var actionRegistry = buildRegistry(actionFragments)

// buildRegistry merges the domain fragments into one map, panicking if two
// fragments register the same action string. A single map literal caught
// duplicate keys at compile time; once entries live in separate files this
// runtime guard restores that protection.
func buildRegistry(fragments []actionFragment) map[string]actionHandlerFunc {
	reg := make(map[string]actionHandlerFunc)
	for _, fragment := range fragments {
		for action, handler := range fragment() {
			if _, dup := reg[action]; dup {
				panic("dispatch: action " + action + " registered by two domain fragments")
			}
			reg[action] = handler
		}
	}
	return reg
}
