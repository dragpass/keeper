package dispatch

import (
	"testing"

	"github.com/dragpass/keeper/internal/keystore/proto"
)

// lv78 A3: the unversioned purge erases chat state, so it is gated by the
// chat runtime lease and revokes the runtime once it erased, like
// chat_state_purge. Unlike that one only the App sends it: the Extension's
// sign-out always names a generation.
func TestUnversionedPurgeIsAnAppOnlyRevocationOnErase(t *testing.T) {
	name := proto.ChatStatePurgeUnversioned
	if name != "chat_state_purge_unversioned" {
		t.Fatalf("action name = %q", name)
	}
	if _, ok := actionRegistry[name]; !ok {
		t.Fatal("chat_state_purge_unversioned is not registered")
	}
	gated, reason := ChatRuntimeClass(name)
	if !gated || reason != ChatRuntimeRevokedPurged {
		t.Fatalf("class = (%v, %q), want gated revoking purged", gated, reason)
	}
	if !ChatRuntimeRevocationDeferred(name) {
		t.Fatal("the revocation must wait for the handler to report an erase")
	}
	if !AppOnly(name) {
		t.Fatal("a Native Messaging frame must not reach the unversioned purge")
	}
	if OnlineDecisionRequired(name) || AccountOnlineDecisionRequired(name) {
		t.Fatal("a local erase needs no API decision")
	}
}

func TestUnversionedPurgeRevokesOnlyAfterAnErase(t *testing.T) {
	name := proto.ChatStatePurgeUnversioned
	erased := proto.BaseResponse{Success: true, Data: proto.ChatStatePurgeResponseData{Purged: true, RemovedConversations: 1}}
	if got := RevocationAfter(name, erased); got != ChatRuntimeRevokedPurged {
		t.Fatalf("after an erase: %q", got)
	}
	kept := proto.BaseResponse{Success: true, Data: proto.ChatStatePurgeResponseData{Kept: proto.ChatStatePurgeKeptSignedIn}}
	if got := RevocationAfter(name, kept); got != "" {
		t.Fatalf("after a kept state: %q", got)
	}
	incomplete := proto.BaseResponse{Data: proto.ChatStatePurgeResponseData{EraseIncomplete: true}}
	if got := RevocationAfter(name, incomplete); got != ChatRuntimeRevokedPurged {
		t.Fatalf("after an incomplete erase: %q", got)
	}
}
