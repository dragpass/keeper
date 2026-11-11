package dispatch

import (
	"slices"
	"testing"
)

// The set the API issues decisions for (ariadne
// internal/services/chat/online_decision.go onlineDecisionActions). Keeper
// must require a decision for exactly these: one Keeper gates and the API
// never issues is unusable, one the API issues and Keeper does not gate is
// open.
func TestOnlineDecisionActionsMatchTheAPIIssuerSet(t *testing.T) {
	want := []string{
		"chat_state_read_outbox",
		"mls_commit_build",
		"mls_commit_confirm",
		"mls_conversation_status",
		"mls_decrypt_batch_for_app_display",
		"mls_encrypt",
		"mls_epoch_comparison",
		"mls_group_create",
		"mls_join",
		"mls_leave_request_sign",
		"mls_mark_sent",
		"mls_process",
		"mls_rejoin_request_sign",
		"mls_room_name_open",
		"mls_room_name_seal",
	}
	got := OnlineDecisionActions()
	if !slices.Equal(got, want) {
		t.Fatalf("online decision actions =\n%v\nwant\n%v", got, want)
	}
	for _, action := range want {
		if !OnlineDecisionRequired(action) {
			t.Fatalf("%s does not require an online decision", action)
		}
		if !AppOnly(action) {
			t.Fatalf("%s needs a decision but a Native Messaging frame may run it", action)
		}
	}
}
