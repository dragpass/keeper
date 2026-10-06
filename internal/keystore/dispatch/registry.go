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
	"sort"

	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/handlers"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// actionHandlerFunc is the unified signature for the dispatcher action map
// ("action registry" — Go pattern terminology, unrelated to the DragPass
// product DragLink inventory).
type actionHandlerFunc func(d handlers.Deps, payload json.RawMessage) proto.BaseResponse

// action is one registry entry: the handler and what the rest of Keeper needs
// to know about it, declared next to the registration instead of in lists kept
// elsewhere. wrap / wrapCapped / direct build one with no flags; the methods
// below add them.
type action struct {
	handle actionHandlerFunc
	// chat is the chat runtime lease class. Every chat action declares one
	// (TestChatActionsDeclareTheirChatRuntimeClass).
	chat chatRuntimeClass
	// revokes is the revocation reason of a gated action that erases chat
	// state: it moves the chat runtime epoch for any caller.
	revokes string
	// mcp marks the actions `@dragpass/mcp` and `dragpass-run` call.
	mcp bool
	// plaintext marks an action whose response carries decrypted user data.
	plaintext bool
}

type chatRuntimeClass uint8

const (
	chatUnclassified chatRuntimeClass = iota
	// chatFree: a read-only report or a signed statement; either caller may
	// run it at any time.
	chatFree
	// chatGated: writes chat state, MLS group state, leaf slots or the
	// KeyPackage pool, or advances the receive state; runs only for the chat
	// runtime holder.
	chatGated
)

// Revocation reasons, carried in chat_runtime_revoked's data.
const (
	ChatRuntimeRevokedPurged = "purged"
	ChatRuntimeRevokedReset  = "reset"
)

func (a action) gated() action    { a.chat = chatGated; return a }
func (a action) chatFree() action { a.chat = chatFree; return a }

func (a action) revoking(reason string) action {
	a.chat = chatGated
	a.revokes = reason
	return a
}

func (a action) onMCP() action            { a.mcp = true; return a }
func (a action) returnsPlaintext() action { a.plaintext = true; return a }

// direct registers a handler that decodes its own payload (the strict decoders
// of the chat and message actions).
func direct(handler actionHandlerFunc) action {
	return action{handle: handler}
}

// wrap adapts a typed handler (func(handlers.Deps, T) proto.BaseResponse) to
// an action. process[T] handles JSON decoding and the Validate call, so wrap
// is a simple delegation.
func wrap[T any](handler func(handlers.Deps, T) proto.BaseResponse) action {
	return direct(func(d handlers.Deps, payload json.RawMessage) proto.BaseResponse {
		return process(payload, func(req T) proto.BaseResponse {
			return handler(d, req)
		})
	})
}

// wrapCapped is wrap plus a ceiling on the raw payload, checked before the
// decode. Used where the caller controls a list inside the request — the wrap
// actions take up to 64 recipients, each able to carry a rotation chain — and
// the refusal has to land before anything is unwrapped rather than after.
func wrapCapped[T any](maxBytes int, handler func(handlers.Deps, T) proto.BaseResponse) action {
	return direct(func(d handlers.Deps, payload json.RawMessage) proto.BaseResponse {
		if len(payload) > maxBytes {
			return errs.CodeResponse(errs.ErrCodeValidation, "payload exceeds the maximum request size")
		}
		return process(payload, func(req T) proto.BaseResponse {
			return handler(d, req)
		})
	})
}

// actionFragment returns one domain's slice of the registry.
type actionFragment func() map[string]action

// actionFragments lists every domain fragment. Keep this order aligned with the
// proto/actions_*.go files.
var actionFragments = []actionFragment{
	coreActions,
	identityActions,
	serverKeyActions,
	groupActions,
	peerKeyActions,
	credentialActions,
	messageActions,
	chatStateActions,
	mlsChatActions,
	archiveActions,
	archiveQuorumActions,
}

// actionRegistry maps action strings to their entries, assembled from the
// domain fragments at package init.
var actionRegistry = buildRegistry(actionFragments)

// RegisteredActionNames returns the sorted Native Messaging action surface.
func RegisteredActionNames() []string {
	actions := make([]string, 0, len(actionRegistry))
	for action := range actionRegistry {
		actions = append(actions, action)
	}
	sort.Strings(actions)
	return actions
}

// buildRegistry merges the domain fragments into one map, panicking if two
// fragments register the same action string. A single map literal caught
// duplicate keys at compile time; once entries live in separate files this
// runtime guard restores that protection.
func buildRegistry(fragments []actionFragment) map[string]action {
	reg := make(map[string]action)
	for _, fragment := range fragments {
		for name, entry := range fragment() {
			if _, dup := reg[name]; dup {
				panic("dispatch: action " + name + " registered by two domain fragments")
			}
			reg[name] = entry
		}
	}
	return reg
}

// ChatRuntimeClass reports whether the chat runtime lease gates action and,
// for a gated action that erases chat state, its revocation reason.
func ChatRuntimeClass(name string) (gated bool, revocation string) {
	entry := actionRegistry[name]
	return entry.chat == chatGated, entry.revokes
}

// ChatRuntimeGatedActions returns the gated action names, sorted.
func ChatRuntimeGatedActions() []string {
	return actionNames(func(a action) bool { return a.chat == chatGated })
}

// MCPCallableActions returns the actions marked onMCP, sorted.
func MCPCallableActions() []string {
	return actionNames(func(a action) bool { return a.mcp })
}

// PlaintextActions returns the actions marked returnsPlaintext, sorted.
func PlaintextActions() []string {
	return actionNames(func(a action) bool { return a.plaintext })
}

func actionNames(keep func(action) bool) []string {
	var names []string
	for name, entry := range actionRegistry {
		if keep(entry) {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}
