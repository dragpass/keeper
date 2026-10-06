package dispatch

import (
	"slices"
	"strings"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/proto"
)

// A chat action has to say whether the chat runtime lease gates it. Leaving a
// new chat writer unmarked used to mean ungated, and the pinned gated list did
// not notice, because nothing compared it with the registry.
func TestChatActionsDeclareTheirChatRuntimeClass(t *testing.T) {
	chatFragments := map[string]bool{}
	for _, fragment := range []actionFragment{chatStateActions, mlsChatActions} {
		for name := range fragment() {
			chatFragments[name] = true
		}
	}
	for name, spec := range actionRegistry {
		chatNamed := strings.HasPrefix(name, "mls_") || strings.HasPrefix(name, "chat_") ||
			strings.HasPrefix(name, "conversation_")
		if (chatNamed || chatFragments[name]) && spec.chat == chatUnclassified {
			t.Errorf("chat action %q declares neither .gated() nor .chatFree()", name)
		}
	}
}

func TestChatRuntimeRevocationsAreGated(t *testing.T) {
	for name, spec := range actionRegistry {
		if spec.revokes != "" && spec.chat != chatGated {
			t.Errorf("%q revokes the chat runtime epoch but is not gated", name)
		}
	}
	gated, reason := ChatRuntimeClass(proto.ChatStatePurge)
	if !gated || reason != ChatRuntimeRevokedPurged {
		t.Fatalf("chat_state_purge = (%v, %q)", gated, reason)
	}
	gated, reason = ChatRuntimeClass(proto.ActionResetDeviceIdentity)
	if !gated || reason != ChatRuntimeRevokedReset {
		t.Fatalf("reset_device_identity = (%v, %q)", gated, reason)
	}
	if gated, reason := ChatRuntimeClass(proto.MLSConversationStatus); gated || reason != "" {
		t.Fatalf("mls_conversation_status = (%v, %q)", gated, reason)
	}
}

// Plaintext leaves the Keeper in a response only from these actions, each an
// approved display carve-out (proto/no_raw_secret_response_test.go). The
// field-name scan there missed the removed *_decrypt_meta actions because
// their plaintext rode in `fields`; this list is declared per action instead.
func TestOnlyTheDisplayCarveOutsReturnPlaintext(t *testing.T) {
	want := []string{
		proto.ActionGroupDecryptWithAadForAppDisplay,
		proto.MLSDecryptBatchForAppDisplay,
		proto.MLSRoomNameOpen,
	}
	slices.Sort(want)
	if got := PlaintextActions(); !slices.Equal(got, want) {
		t.Fatalf("plaintext-returning actions = %v, want %v; a new one is a "+
			"security design decision, not a test update", got, want)
	}
}
