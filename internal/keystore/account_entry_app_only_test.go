package keystore

import (
	"testing"

	"github.com/dragpass/keeper/internal/keystore/proto"
)

// accountEntryActions are the App's account entry (signup, recovery, RK24
// reissue, and sign-in with a key one of them staged). The Extension binds no
// Keeper port for any of them, so Keeper refuses them on Native Messaging.
var accountEntryActions = []string{
	proto.ActionAuthSignupPrepare,
	proto.ActionAuthSignupAbort,
	proto.ActionAuthRecoveryReissuePrepare,
	proto.ActionAuthRecoveryBegin,
	proto.ActionAuthRecoveryPrepare,
	proto.ActionAuthRecoveryAbort,
	proto.ActionAuthLoginPendingSignAlias,
	proto.ActionAuthLoginPendingSignChallenge,
}

func TestAccountEntryActionsAreRefusedOnNativeMessagingAndRunNothing(t *testing.T) {
	app, _, store := newLeaseApp(t)
	for _, action := range accountEntryActions {
		before := store.calls.Load()
		response := app.HandleRequest([]byte(`{"action":"` + action + `","request_id":"x","payload":{"alias":"alice","recovery_key":"x","password":"x","publickey":"x","new_public_key":"x"}}`))
		if response.Success || response.ErrorCode != ErrCodeChatAppCallerRequired || response.RequestID != "x" {
			t.Fatalf("%s from Native Messaging: %+v", action, response)
		}
		if store.calls.Load() != before {
			t.Fatalf("%s ran although it was refused", action)
		}
	}
}

func TestAccountEntryActionsReachTheirHandlerFromTheApp(t *testing.T) {
	app, _, _ := newLeaseApp(t)
	for _, action := range accountEntryActions {
		response := app.HandleAppRequest(sessionA, "", []byte(`{"action":"`+action+`","request_id":"x","payload":{}}`))
		if response.ErrorCode == ErrCodeChatAppCallerRequired || response.ErrorCode == ErrCodeChatRuntimeLeaseRequired {
			t.Fatalf("%s from the App was refused at the gate: %+v", action, response)
		}
	}
}

// The refusal names no chat action: most App-only actions are not chat.
func TestAppCallerRequiredMessageIsNotChatSpecific(t *testing.T) {
	app, _, _ := newLeaseApp(t)
	response := app.HandleRequest([]byte(`{"action":"` + proto.ActionAuthSignupPrepare + `"}`))
	if response.Error != "only the DragPass app may run this action" {
		t.Fatalf("refusal message: %q", response.Error)
	}
}
