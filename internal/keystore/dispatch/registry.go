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
	// revokesOnErase defers that revocation until the handler reports it
	// erased the state it named (lv78): a purge that matched no current
	// sign-in must not end the current sign-in's runtime.
	revokesOnErase bool
	// mcp marks the actions `@dragpass/mcp` and `dragpass-run` call.
	mcp bool
	// plaintext marks an action whose response carries decrypted user data.
	plaintext bool
	// appOnly marks an action only the authenticated App caller (local RPC
	// session) may run; a Native Messaging frame is refused before its
	// handler. Chat runs only in the App, so every gated chat action is one.
	appOnly bool
	// e2eNativeFixture lets a keeper_e2e build serve this App-only action to
	// a Native Messaging frame, for the Extension's E2E organization
	// fixtures. A release build ignores it (nativeFixturesAllowed).
	e2eNativeFixture bool
	// onlineDecision marks a protected App MLS action that runs only with a
	// verified, unused API online decision for this call (lv78 D1). The App
	// lease and the chat state permit alone do not admit it.
	onlineDecision bool
}

type chatRuntimeClass uint8

const (
	chatUnclassified chatRuntimeClass = iota
	// chatFree: a read-only report or a signed statement; either caller may
	// run it at any time.
	chatFree
	// chatGated: writes chat state, MLS group state, leaf slots or the
	// KeyPackage pool, or advances the receive state; runs only for the App
	// session holding the chat runtime lease.
	chatGated
)

// Revocation reasons, carried in chat_runtime_revoked's data.
const (
	ChatRuntimeRevokedPurged = "purged"
	ChatRuntimeRevokedReset  = "reset"
)

// gated is an App-only chat action. revoking is gated but not App-only: the
// Extension's logout and device reset erase chat state too.
func (a action) gated() action    { a.chat = chatGated; a.appOnly = true; return a }
func (a action) chatFree() action { a.chat = chatFree; return a }

// revokingOnErase is revoking, applied only after the handler erased state.
func (a action) revokingOnErase(reason string) action {
	a = a.revoking(reason)
	a.revokesOnErase = true
	return a
}

func (a action) revoking(reason string) action {
	a.chat = chatGated
	a.revokes = reason
	return a
}

// appOnlyAction marks an ungated action App-only, such as a chat action that
// returns plaintext.
func (a action) appOnlyAction() action { a.appOnly = true; return a }

// e2eNativeFixture marks an App-only action the Extension's E2E fixtures may
// still run over Native Messaging in a keeper_e2e build.
func (a action) e2eFixtureOnNative() action { a.e2eNativeFixture = true; return a }

// needsOnlineDecision marks an action that runs only through the online
// decision path (lv78 K3).
func (a action) needsOnlineDecision() action { a.onlineDecision = true; return a }

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
	changeTrackActions,
	peerKeyActions,
	credentialActions,
	messageActions,
	chatStateActions,
	mlsChatActions,
	archiveActions,
	archiveQuorumActions,
	e2eActions,
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

// ChatRuntimeRevocationDeferred reports whether action's revocation waits for
// its handler's answer (see RevocationAfter) instead of happening at admission.
func ChatRuntimeRevocationDeferred(name string) bool {
	return actionRegistry[name].revokesOnErase
}

// RevocationAfter is the revocation reason a deferred-revocation action earns
// with resp: a successful purge that reports it erased state revokes, and so
// does a failed purge whose erase steps ran (erase_incomplete), because the
// state it named is no longer intact.
func RevocationAfter(name string, resp proto.BaseResponse) string {
	entry := actionRegistry[name]
	if !entry.revokesOnErase {
		return ""
	}
	data, ok := resp.Data.(proto.ChatStatePurgeResponseData)
	if !ok {
		return ""
	}
	if (resp.Success && data.Purged) || (!resp.Success && data.EraseIncomplete) {
		return entry.revokes
	}
	return ""
}

// OnlineDecisionRequired reports whether action runs only with a verified API
// online decision for the call.
func OnlineDecisionRequired(name string) bool {
	return actionRegistry[name].onlineDecision
}

// OnlineDecisionActions returns the actions that need an online decision, sorted.
func OnlineDecisionActions() []string {
	return actionNames(func(a action) bool { return a.onlineDecision })
}

// AppOnly reports whether only the authenticated App caller may run action.
func AppOnly(name string) bool {
	return refusedToNative(actionRegistry[name])
}

// AppOnlyActions returns the App-only action names, sorted.
func AppOnlyActions() []string {
	return actionNames(refusedToNative)
}

// NativeE2EFixtureActions returns the App-only actions a keeper_e2e build
// serves to Native Messaging frames for the Extension's E2E fixtures, sorted.
// NativeFixturesAllowed reports whether this build does.
func NativeE2EFixtureActions() []string {
	return actionNames(func(a action) bool { return a.appOnly && a.e2eNativeFixture })
}

// NativeFixturesAllowed is true only in a keeper_e2e build.
func NativeFixturesAllowed() bool { return nativeFixturesAllowed }

func refusedToNative(a action) bool {
	return a.appOnly && !(a.e2eNativeFixture && nativeFixturesAllowed)
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
