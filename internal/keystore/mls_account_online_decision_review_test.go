package keystore

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/dragpass/keeper/config"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// lv78 A1b review A3: execute reads the sign-in again and refuses a record
// that says signed out, even one whose generation did not move (a sign-out
// always moves it; this pins the check of the mark itself).
func TestAccountDecisionIsRefusedWhenTheRecordSaysSignedOut(t *testing.T) {
	call := accountCalls()["mls_device_revoke_sign"]
	f := newOnlineFixture(t)
	d := f.decideAccount(t, call, f.prepareAccount(t, call))
	binding, found, err := keychain.GetAccountBinding(f.store)
	if err != nil || !found {
		t.Fatalf("binding: found=%v err=%v", found, err)
	}
	binding.SignedOut = true
	encoded, err := json.Marshal(binding)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.store.Set(config.Service, config.AccountBinding, string(encoded)); err != nil {
		t.Fatal(err)
	}
	refusedBeforeTheAccountAction(t, func() proto.BaseResponse { return f.executeAccount(call, call.request, d) })
}

// lv78 A1b review A3, phase (c): the decision's own wall-clock expiry is
// checked again after the action, not only the challenge deadline. A
// decision the API issued a few seconds before the challenge expires earlier
// than the challenge; its output is withheld once that expiry passed.
func TestAccountOutputIsWithheldWhenTheDecisionExpiresDuringTheCall(t *testing.T) {
	call := accountCalls()["mls_device_revoke_sign"]
	f := newOnlineFixture(t)
	prepared := f.prepareAccount(t, call)
	now := f.clock.Now().Unix()
	d := f.signAccount(t, proto.MLSAccountOnlineDecision{
		Challenge: prepared.Challenge, AccountID: onlineAccount, DeviceID: onlineDevice,
		TokenID: onlineToken, SessionIssuedAtNanos: onlineSession, Action: call.action,
		Target: call.target, RequestCommitment: prepared.RequestCommitment,
		IssuedAt: now - 5, ExpiresAt: now + 5, ServerKeyVersion: 1,
	})
	ran := false
	restore := setChatOnlineAfterWorkForTesting(func() {
		ran = true
		f.clock.advance(6 * time.Second)
	})
	defer restore()
	response := f.executeAccount(call, call.request, d)
	if !ran || response.Success || response.ErrorCode != ErrCodeChatOnlineOutputWithheld || response.Data != nil {
		t.Fatalf("ran=%v, want %s without data, got %+v", ran, ErrCodeChatOnlineOutputWithheld, response)
	}
}

// lv78 A1b review A3, defense in depth at the gate: an App call marked as
// admitted by a chat decision does not run an account-level action, and one
// marked as admitted by an account decision does not run a chat action. The
// prepare steps already refuse the other set; this pins the gate on its own.
func TestGateKeepsChatAndAccountDecisionsApart(t *testing.T) {
	f := newOnlineFixture(t)
	for name, tc := range map[string]struct {
		caller chatRuntimeCaller
		action string
	}{
		"chat decision, account action": {
			caller: chatRuntimeCaller{app: true, session: sessionA, epoch: f.epoch, chatWork: true, onlineDecision: true},
			action: proto.ActionMLSLeafDeclare,
		},
		"account decision, chat action": {
			caller: chatRuntimeCaller{app: true, session: sessionA, epoch: f.epoch, chatWork: true, accountOnlineDecision: true},
			action: "mls_encrypt",
		},
	} {
		t.Run(name, func(t *testing.T) {
			response, admitted := f.app.chatRuntimeGate(tc.caller)(tc.action)
			if admitted || response.ErrorCode != ErrCodeChatOnlineDecisionRequired {
				t.Fatalf("admitted=%v %+v", admitted, response)
			}
		})
	}
}
