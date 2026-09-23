// registry_mcp_surface_test.go — regression guard for the boundary between the
// AI agent control plane and DragPass chat.
//
// The dispatcher has one action registry and the Keeper cannot tell who
// launched it: the extension service worker, the popup, `@dragpass/mcp`, and
// `dragpass-run` all speak the same protocol to the same binary. So "MCP does
// not call the chat actions" is a code convention, and a convention lasts until
// the PR that adds a call. Two things are supposed to keep it from becoming
// one: the conversation-state actions demand a server-signed permit that only
// user-JWT routes issue, and the set of actions MCP may call is pinned here so
// growing it is a visible decision rather than a line in a diff.
//
// The list comes from the audit in dragpass-control-plane
// docs/security/adr-ratchet-state-storage.md §3.2, which walked every Keeper
// call in packages/mcp: a version gate, the group-session pair, and the two
// credential sinks. Everything MCP asks the Keeper for is a credential.
//
// This test cannot reach into the TypeScript package, so it does not claim to.
// What it asserts is the Keeper half: the pinned set is real, it is exactly
// five, and no chat or conversation action is in it.

package dispatch

import (
	"strings"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/proto"
)

// mcpCallableActions is the whole Keeper surface `@dragpass/mcp` and
// `dragpass-run` use. Adding an entry means widening what a model can reach
// through a tool call, which is the decision this constant exists to surface.
var mcpCallableActions = []string{
	proto.ActionPing,
	proto.ActionGroupSessionOpen,
	proto.ActionGroupSessionClose,
	proto.ActionCredentialHTTPRequest,
	proto.ActionCredentialExecRequest,
}

func TestMCPCallableActions_AreRegisteredAndExactlyFive(t *testing.T) {
	if len(mcpCallableActions) != 5 {
		t.Fatalf("mcpCallableActions has %d entries, want 5 — widening the MCP "+
			"surface is a security decision, not a test update.", len(mcpCallableActions))
	}
	for _, action := range mcpCallableActions {
		if _, ok := actionRegistry[action]; !ok {
			t.Errorf("pinned MCP action %q is not registered; the pin is stale", action)
		}
	}
}

func TestMCPCallableActions_ExcludeChatState(t *testing.T) {
	pinned := map[string]bool{}
	for _, action := range mcpCallableActions {
		pinned[action] = true
	}
	for _, action := range chatStateActionNames(t) {
		if pinned[action] {
			t.Errorf("conversation-state action %q is on the MCP surface; chat state "+
				"must not be reachable from a tool call", action)
		}
	}
	// The chat reveal path is the same boundary one layer over.
	if pinned[proto.ActionConversationDecryptBatchForAppDisplay] {
		t.Error("the chat reveal action is on the MCP surface")
	}
	if pinned[proto.MLSDecryptBatchForAppDisplay] {
		t.Error("the chat v2 reveal action is on the MCP surface")
	}
}

// A model that could reach declare could vouch for a leaf key under the
// user's account key, which is the one statement the MLS identity check
// trusts; one that could reach promote or abort could choose which key signs.
func TestMCPCallableActions_ExcludeTheMLSLeafLifecycle(t *testing.T) {
	for _, leaf := range []string{
		proto.ActionMLSLeafDeclare, proto.ActionMLSLeafPromote, proto.ActionMLSLeafAbort, proto.ActionMLSLeafStatus,
	} {
		if _, ok := actionRegistry[leaf]; !ok {
			t.Fatalf("%s is not registered; this guard checks nothing", leaf)
		}
		for _, action := range mcpCallableActions {
			if action == leaf {
				t.Fatalf("%s is on the MCP surface", leaf)
			}
		}
	}
}

// A model that could reach this could put this device's leaf into any group
// whose member the server hands the KeyPackage to.
func TestMCPCallableActions_ExcludeMLSKeyPackageGenerate(t *testing.T) {
	for _, action := range mcpCallableActions {
		if action == proto.MLSKeyPackageGenerate {
			t.Fatal("mls_key_package_generate is on the MCP surface")
		}
	}
	if _, ok := actionRegistry[proto.MLSKeyPackageGenerate]; !ok {
		t.Fatal("mls_key_package_generate is not registered; this guard checks nothing")
	}
}

// mlsChatActionNames is every action that reads or writes the MLS group state.
// A model that could reach any of them could add a leaf to a conversation,
// move its epoch, or encrypt and read under this account's name.
var mlsChatActionNames = []string{
	proto.MLSGroupCreate,
	proto.MLSGroupDiscardUnaccepted,
	proto.MLSCommitBuild,
	proto.MLSCommitConfirm,
	proto.MLSProcess,
	proto.MLSJoin,
	proto.MLSEncrypt,
	proto.MLSMarkSent,
	proto.MLSDecryptBatchForAppDisplay,
	proto.MLSConversationStatus,
}

func TestMCPCallableActions_ExcludeTheMLSChatActions(t *testing.T) {
	pinned := map[string]bool{}
	for _, action := range mcpCallableActions {
		pinned[action] = true
	}
	for _, action := range mlsChatActionNames {
		if _, ok := actionRegistry[action]; !ok {
			t.Fatalf("%s is not registered; this guard checks nothing", action)
		}
		if pinned[action] {
			t.Errorf("mls chat action %q is on the MCP surface", action)
		}
	}
}

// TestMLSChatActions_AreExactlyTheRegistered keeps mlsChatActionNames honest
// the way the chat_state_* guard below keeps its set honest: an MLS chat
// action registered without being named here fails rather than slipping past
// the MCP check above.
func TestMLSChatActions_AreExactlyTheRegistered(t *testing.T) {
	want := map[string]bool{}
	for _, action := range mlsChatActionNames {
		want[action] = true
	}
	got := mlsChatActions()
	if len(got) != len(want) {
		t.Fatalf("registered mls chat actions = %d, want %d", len(got), len(want))
	}
	for action := range got {
		if !want[action] {
			t.Errorf("mls chat action %q is registered but not guarded", action)
		}
	}
}

// TestChatStateActions_AreExactlyTheFiveRegistered keeps the set this guard
// checks honest: a sixth conversation-state action added without a thought
// about the boundary fails here rather than passing unnoticed.
func TestChatStateActions_AreExactlyTheFiveRegistered(t *testing.T) {
	want := map[string]bool{
		proto.ChatStateReserveSend:  true,
		proto.ChatStateCommitOutbox: true,
		proto.ChatStateReadOutbox:   true,
		proto.ChatStateMarkReceived: true,
		proto.ChatStatePurge:        true,
	}
	got := chatStateActionNames(t)
	if len(got) != len(want) {
		t.Fatalf("registered chat state actions = %v, want %d entries", got, len(want))
	}
	for _, action := range got {
		if !want[action] {
			t.Errorf("unexpected chat state action %q", action)
		}
	}
}

func chatStateActionNames(t *testing.T) []string {
	t.Helper()
	var names []string
	for action := range actionRegistry {
		if strings.HasPrefix(action, "chat_state_") {
			names = append(names, action)
		}
	}
	if len(names) == 0 {
		t.Fatal("no chat_state_* actions are registered — the prefix scan is broken")
	}
	return names
}
