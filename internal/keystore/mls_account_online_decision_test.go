package keystore

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dragpass/keeper/config"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

const (
	accountOnlineOtherDevice = "d7777777-4444-4444-8444-444444444444"
	accountOnlineRemoved     = "a8888888-1111-4111-8111-111111111111"
	accountOnlineTakeover    = "f9999999-6666-4666-8666-666666666666"
)

// accountCall is one account-level call: the action, its exact request, the
// takeover request the App names (handover only) and the target Keeper must
// derive.
type accountCall struct {
	action   string
	request  json.RawMessage
	takeover string
	target   string
}

func rawJSON(v any) json.RawMessage {
	raw, _ := json.Marshal(v)
	return raw
}

func accountCalls() map[string]accountCall {
	return map[string]accountCall{
		"mls_leaf_declare": {action: "mls_leaf_declare", request: rawJSON(map[string]any{
			"challenge_token": "c", "server_signature": "AA==", "server_key_version": 1,
			"account_id": onlineAccount, "device_id": onlineDevice, "not_before": 1, "not_after": 2, "reason": "enroll",
		}), target: "device:" + onlineDevice},
		"mls_leaf_promote": {action: "mls_leaf_promote", request: rawJSON(map[string]any{
			"acceptance_token": "t", "server_signature": "AA==", "server_key_version": 1,
		}), target: "device:" + onlineDevice},
		"mls_key_package_generate": {action: "mls_key_package_generate", request: rawJSON(map[string]any{
			"challenge_token": "c", "server_signature": "AA==", "server_key_version": 1,
			"account_id": onlineAccount, "device_id": onlineDevice, "count": 1,
		}), target: "device:" + onlineDevice},
		"mls_leaf_handover_sign": {action: "mls_leaf_handover_sign", request: rawJSON(map[string]any{
			"account_id": onlineAccount, "new_declaration": map[string]any{}, "expires_at": 1,
		}), takeover: accountOnlineTakeover, target: "takeover:" + accountOnlineTakeover},
		"mls_device_revoke_sign": {action: "mls_device_revoke_sign", request: rawJSON(map[string]any{
			"account_id": onlineAccount, "device_id": accountOnlineOtherDevice,
		}), target: "device:" + accountOnlineOtherDevice},
		"org_member_removal_sign": {action: "org_member_removal_sign", request: rawJSON(map[string]any{
			"org_id": onlineOrg, "removed_account_id": accountOnlineRemoved, "admin_account_id": onlineAccount,
		}), target: "org:" + onlineOrg + "/account:" + accountOnlineRemoved},
	}
}

func (f *onlineFixture) prepareAccount(t *testing.T, call accountCall) proto.MLSAccountOnlinePrepareResponseData {
	t.Helper()
	response := f.app.PrepareMLSAccountOnline("", proto.MLSAccountOnlinePrepareRequest{
		Action: call.action, Request: call.request, TokenID: onlineToken,
		SessionIssuedAtNanos: onlineSession, TakeoverRequestID: call.takeover,
	})
	if !response.Success {
		t.Fatalf("prepare %s: %+v", call.action, response)
	}
	data, ok := response.Data.(proto.MLSAccountOnlinePrepareResponseData)
	if !ok || data.Challenge == "" || len(data.RequestCommitment) != 64 {
		t.Fatalf("prepare data: %+v", response.Data)
	}
	return data
}

// decideAccount is what the API signs for prepared, at the fixture clock.
func (f *onlineFixture) decideAccount(t *testing.T, call accountCall, prepared proto.MLSAccountOnlinePrepareResponseData) proto.MLSAccountOnlineDecision {
	t.Helper()
	now := f.clock.Now().Unix()
	return f.signAccount(t, proto.MLSAccountOnlineDecision{
		Challenge: prepared.Challenge, AccountID: onlineAccount, DeviceID: onlineDevice,
		TokenID: onlineToken, SessionIssuedAtNanos: onlineSession, Action: call.action,
		Target: call.target, RequestCommitment: prepared.RequestCommitment,
		IssuedAt: now, ExpiresAt: now + 10, ServerKeyVersion: 1,
	})
}

func (f *onlineFixture) signAccount(t *testing.T, d proto.MLSAccountOnlineDecision) proto.MLSAccountOnlineDecision {
	t.Helper()
	d.Signature = f.pss(t, proto.MLSAccountOnlineDecisionCanonical(d))
	return d
}

func (f *onlineFixture) pss(t *testing.T, canonical string) string {
	t.Helper()
	sum := sha256.Sum256([]byte(canonical))
	sig, err := rsa.SignPSS(rand.Reader, f.key, crypto.SHA256, sum[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256})
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(sig)
}

func (f *onlineFixture) executeAccount(call accountCall, request json.RawMessage, d proto.MLSAccountOnlineDecision) proto.BaseResponse {
	return f.app.ExecuteMLSAccountOnline(sessionA, f.epoch, "", proto.MLSAccountOnlineExecuteRequest{Action: call.action, Request: request, Decision: &d})
}

// accountRan executes and reports whether the action's handler ran, with
// the answer.
func accountRan(execute func() proto.BaseResponse) (bool, proto.BaseResponse) {
	ran := false
	restore := setChatOnlineAfterWorkForTesting(func() { ran = true })
	defer restore()
	response := execute()
	return ran, response
}

// lv78 A1b: a decision the API signed under the account domain for the
// challenge Keeper minted, bound to this account, device, session, action,
// target and request, admits exactly that call, for each of the six actions.
func TestValidAccountDecisionAdmitsEachAction(t *testing.T) {
	for name, call := range accountCalls() {
		t.Run(name, func(t *testing.T) {
			f := newOnlineFixture(t)
			prepared := f.prepareAccount(t, call)
			if prepared.Target != call.target {
				t.Fatalf("prepared target %q, want %q", prepared.Target, call.target)
			}
			ran, response := accountRan(func() proto.BaseResponse {
				return f.executeAccount(call, call.request, f.decideAccount(t, call, prepared))
			})
			if !ran || response.ErrorCode == ErrCodeChatOnlineDecisionRefused || response.ErrorCode == ErrCodeChatOnlineDecisionRequired ||
				response.ErrorCode == ErrCodeChatOnlineOutputWithheld {
				t.Fatalf("a valid decision did not reach the handler: ran=%v %+v", ran, response)
			}
		})
	}
}

func refusedBeforeTheAccountAction(t *testing.T, execute func() proto.BaseResponse) {
	t.Helper()
	ran, response := accountRan(execute)
	refusedByDecision(t, response)
	if ran {
		t.Fatal("the account action ran before the decision was refused")
	}
}

// lv78 A1b: every bound field must equal what the challenge was minted for.
func TestAccountDecisionBoundToSomethingElseIsRefused(t *testing.T) {
	call := accountCalls()["mls_device_revoke_sign"]
	for name, change := range map[string]func(*proto.MLSAccountOnlineDecision){
		"account":       func(d *proto.MLSAccountOnlineDecision) { d.AccountID = "a9999999-1111-4111-8111-111111111111" },
		"device":        func(d *proto.MLSAccountOnlineDecision) { d.DeviceID = "d9999999-4444-4444-8444-444444444444" },
		"token":         func(d *proto.MLSAccountOnlineDecision) { d.TokenID = "e9999999-5555-4555-8555-555555555555" },
		"session start": func(d *proto.MLSAccountOnlineDecision) { d.SessionIssuedAtNanos++ },
		"action":        func(d *proto.MLSAccountOnlineDecision) { d.Action = "mls_leaf_declare" },
		"target":        func(d *proto.MLSAccountOnlineDecision) { d.Target = "device:" + onlineDevice },
		"commitment":    func(d *proto.MLSAccountOnlineDecision) { d.RequestCommitment = strings.Repeat("ab", 32) },
	} {
		t.Run(name, func(t *testing.T) {
			f := newOnlineFixture(t)
			d := f.decideAccount(t, call, f.prepareAccount(t, call))
			change(&d)
			refusedBeforeTheAccountAction(t, func() proto.BaseResponse { return f.executeAccount(call, call.request, f.signAccount(t, d)) })
		})
	}
}

// lv78 A1b: the request is bound byte for byte, and only as its action.
func TestAccountDecisionForAnotherRequestIsRefused(t *testing.T) {
	call := accountCalls()["mls_device_revoke_sign"]
	t.Run("changed request", func(t *testing.T) {
		f := newOnlineFixture(t)
		d := f.decideAccount(t, call, f.prepareAccount(t, call))
		changed := rawJSON(map[string]any{"account_id": onlineAccount, "device_id": "d6666666-4444-4444-8444-444444444444"})
		refusedBeforeTheAccountAction(t, func() proto.BaseResponse { return f.executeAccount(call, changed, d) })
	})
	t.Run("other action", func(t *testing.T) {
		f := newOnlineFixture(t)
		d := f.decideAccount(t, call, f.prepareAccount(t, call))
		other := call
		other.action = "mls_leaf_promote"
		refusedBeforeTheAccountAction(t, func() proto.BaseResponse { return f.executeAccount(other, call.request, d) })
	})
}

// lv78 A1b, domain separation: the same fields signed by the pinned key as a
// chat decision, or by any other key, do not admit an account action.
func TestAccountDecisionSignedUnderAnotherDomainOrKeyIsRefused(t *testing.T) {
	call := accountCalls()["org_member_removal_sign"]
	t.Run("chat domain", func(t *testing.T) {
		f := newOnlineFixture(t)
		d := f.decideAccount(t, call, f.prepareAccount(t, call))
		d.Signature = f.pss(t, strings.Replace(proto.MLSAccountOnlineDecisionCanonical(d),
			proto.MLSAccountOnlineDecisionDomain, proto.ChatOnlineDecisionDomain, 1))
		refusedBeforeTheAccountAction(t, func() proto.BaseResponse { return f.executeAccount(call, call.request, d) })
	})
	t.Run("another key", func(t *testing.T) {
		f := newOnlineFixture(t)
		prepared := f.prepareAccount(t, call)
		other, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		pinned := f.key
		f.key = other
		forged := f.decideAccount(t, call, prepared)
		f.key = pinned
		refusedBeforeTheAccountAction(t, func() proto.BaseResponse { return f.executeAccount(call, call.request, forged) })
	})
}

// lv78 A1b: an account challenge is not a chat challenge and back. Each path
// keeps its own challenges, so a decision of one kind never meets a
// challenge of the other.
func TestAccountAndChatChallengesDoNotCross(t *testing.T) {
	t.Run("account challenge on the chat path", func(t *testing.T) {
		f := newOnlineFixture(t)
		call := accountCalls()["mls_device_revoke_sign"]
		prepared := f.prepareAccount(t, call)
		now := f.clock.Now().Unix()
		chat := f.sign(t, proto.ChatOnlineDecision{
			Challenge: prepared.Challenge, AccountID: onlineAccount, DeviceID: onlineDevice,
			TokenID: onlineToken, SessionIssuedAtNanos: onlineSession, Action: "mls_encrypt",
			OrgID: onlineOrg, ConversationID: onlineConv, RequestCommitment: prepared.RequestCommitment,
			IssuedAt: now, ExpiresAt: now + 10, ServerKeyVersion: 1,
		})
		refusedBeforeTheAccountAction(t, func() proto.BaseResponse { return f.execute("mls_encrypt", onlineRequest(onlineConv), chat) })
	})
	t.Run("chat challenge on the account path", func(t *testing.T) {
		f := newOnlineFixture(t)
		call := accountCalls()["mls_device_revoke_sign"]
		prepared := f.prepare(t, "mls_encrypt", onlineRequest(onlineConv))
		d := f.decideAccount(t, call, proto.MLSAccountOnlinePrepareResponseData{
			Challenge: prepared.Challenge, RequestCommitment: prepared.RequestCommitment, Target: call.target,
		})
		refusedBeforeTheAccountAction(t, func() proto.BaseResponse { return f.executeAccount(call, call.request, d) })
	})
}

// lv78 A1b: prepare mints a challenge only for a call a decision could
// admit: an account-level action, for the signed-in account and this device,
// with the target the action names.
func TestAccountPrepareRefusesACallNoDecisionCouldAdmit(t *testing.T) {
	calls := accountCalls()
	with := func(c accountCall, field string, value any) accountCall {
		var r map[string]any
		_ = json.Unmarshal(c.request, &r)
		r[field] = value
		c.request = rawJSON(r)
		return c
	}
	noTakeover := calls["mls_leaf_handover_sign"]
	noTakeover.takeover = ""
	badTakeover := calls["mls_leaf_handover_sign"]
	badTakeover.takeover = "not-a-uuid"
	strayTakeover := calls["mls_device_revoke_sign"]
	strayTakeover.takeover = accountOnlineTakeover
	for name, tc := range map[string]struct {
		call   accountCall
		before func(*onlineFixture) error
	}{
		"a chat action":                       {call: accountCall{action: "mls_encrypt", request: onlineRequest(onlineConv)}},
		"an action without issuer authority":  {call: accountCall{action: "mls_leaf_abort", request: rawJSON(map[string]any{})}},
		"declare for another device":          {call: with(calls["mls_leaf_declare"], "device_id", accountOnlineOtherDevice)},
		"declare for another account":         {call: with(calls["mls_leaf_declare"], "account_id", accountOnlineRemoved)},
		"KeyPackages for another device":      {call: with(calls["mls_key_package_generate"], "device_id", accountOnlineOtherDevice)},
		"revocation for another account":      {call: with(calls["mls_device_revoke_sign"], "account_id", accountOnlineRemoved)},
		"revocation of a malformed device":    {call: with(calls["mls_device_revoke_sign"], "device_id", "D7777777-4444-4444-8444-444444444444")},
		"removal signed for another admin":    {call: with(calls["org_member_removal_sign"], "admin_account_id", accountOnlineRemoved)},
		"handover for another account":        {call: with(calls["mls_leaf_handover_sign"], "account_id", accountOnlineRemoved)},
		"handover without its takeover":       {call: noTakeover},
		"handover with a malformed takeover":  {call: badTakeover},
		"a takeover named for another action": {call: strayTakeover},
		"a request that is not a JSON object": {call: accountCall{action: "mls_leaf_promote", request: json.RawMessage(`[]`)}},
		"signed out": {call: calls["mls_leaf_promote"], before: func(f *onlineFixture) error {
			_, _, err := keychain.SignOutAccountBinding(f.store)
			return err
		}},
		"no device id": {call: calls["mls_leaf_promote"], before: func(f *onlineFixture) error {
			return f.store.Delete(config.Service, config.DeviceID)
		}},
	} {
		t.Run(name, func(t *testing.T) {
			f := newOnlineFixture(t)
			if tc.before != nil {
				if err := tc.before(f); err != nil {
					t.Fatal(err)
				}
			}
			response := f.app.PrepareMLSAccountOnline("", proto.MLSAccountOnlinePrepareRequest{
				Action: tc.call.action, Request: tc.call.request, TokenID: onlineToken,
				SessionIssuedAtNanos: onlineSession, TakeoverRequestID: tc.call.takeover,
			})
			refusedByDecision(t, response)
			if pending := len(f.app.accountOnline.entries); pending != 0 {
				t.Fatalf("%d challenges minted for a refused prepare", pending)
			}
		})
	}
}

// lv78 A1b: the decision's wall-clock window, its key version and the
// challenge deadline hold as for chat; a refusal leaves the challenge for the
// right decision.
func TestAccountDecisionOutsideItsWindowIsRefused(t *testing.T) {
	call := accountCalls()["mls_leaf_promote"]
	for name, shift := range map[string]int64{"expired": -10, "issued too far ahead": 6} {
		t.Run(name, func(t *testing.T) {
			f := newOnlineFixture(t)
			valid := f.decideAccount(t, call, f.prepareAccount(t, call))
			d := valid
			d.IssuedAt += shift
			d.ExpiresAt += shift
			refusedBeforeTheAccountAction(t, func() proto.BaseResponse { return f.executeAccount(call, call.request, f.signAccount(t, d)) })
			if ran, response := accountRan(func() proto.BaseResponse { return f.executeAccount(call, call.request, valid) }); !ran {
				t.Fatalf("the challenge did not survive a decision outside its window: %+v", response)
			}
		})
	}
	t.Run("version 0", func(t *testing.T) {
		f := newOnlineFixture(t)
		if err := keychain.SaveActiveServerKeyVersion(f.store, 1); err != nil {
			t.Fatal(err)
		}
		d := f.decideAccount(t, call, f.prepareAccount(t, call))
		d.ServerKeyVersion = 0
		refusedBeforeTheAccountAction(t, func() proto.BaseResponse { return f.executeAccount(call, call.request, f.signAccount(t, d)) })
	})
	t.Run("challenge past its deadline", func(t *testing.T) {
		f := newOnlineFixture(t)
		prepared := f.prepareAccount(t, call)
		f.clock.advance(proto.MLSAccountOnlineDecisionTTLSeconds * time.Second)
		refusedBeforeTheAccountAction(t, func() proto.BaseResponse {
			return f.executeAccount(call, call.request, f.decideAccount(t, call, prepared))
		})
	})
}

// lv78 A1b: a sign-out, another sign-in, a device reset or another chat
// sign-in between prepare and execute ends the challenge.
func TestAccountDecisionAfterTheSignInChangedIsRefused(t *testing.T) {
	call := accountCalls()["mls_device_revoke_sign"]
	for name, change := range map[string]func(*onlineFixture) error{
		"signed in again": func(f *onlineFixture) error {
			_, _, err := keychain.SetAccountBinding(f.store, onlineAccount, "alice", true)
			return err
		},
		"signed out": func(f *onlineFixture) error {
			_, _, err := keychain.SignOutAccountBinding(f.store)
			return err
		},
		"device reset": func(f *onlineFixture) error {
			return f.store.Set(config.Service, config.DeviceID, "d9999999-4444-4444-8444-444444444444")
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newOnlineFixture(t)
			d := f.decideAccount(t, call, f.prepareAccount(t, call))
			if err := change(f); err != nil {
				t.Fatal(err)
			}
			refusedBeforeTheAccountAction(t, func() proto.BaseResponse { return f.executeAccount(call, call.request, d) })
		})
	}
	t.Run("another chat sign-in", func(t *testing.T) {
		f := newOnlineFixture(t)
		response := f.app.PrepareMLSAccountOnline("an-earlier-chat-sign-in", proto.MLSAccountOnlinePrepareRequest{
			Action: call.action, Request: call.request, TokenID: onlineToken, SessionIssuedAtNanos: onlineSession,
		})
		prepared, ok := response.Data.(proto.MLSAccountOnlinePrepareResponseData)
		if !response.Success || !ok {
			t.Fatalf("prepare: %+v", response)
		}
		d := f.decideAccount(t, call, prepared)
		refusedBeforeTheAccountAction(t, func() proto.BaseResponse { return f.executeAccount(call, call.request, d) })
	})
}

// lv78 A1b: a refused decision leaves the challenge; a valid one is single
// use, also under concurrency.
func TestAccountDecisionIsSingleUse(t *testing.T) {
	call := accountCalls()["mls_device_revoke_sign"]
	f := newOnlineFixture(t)
	valid := f.decideAccount(t, call, f.prepareAccount(t, call))
	const racers = 8
	start := make(chan struct{})
	results := make(chan proto.BaseResponse, racers)
	var ready sync.WaitGroup
	ready.Add(racers)
	for range racers {
		go func() {
			ready.Done()
			<-start
			results <- f.executeAccount(call, call.request, valid)
		}()
	}
	ready.Wait()
	close(start)
	admittedCount := 0
	for range racers {
		if r := <-results; r.ErrorCode != ErrCodeChatOnlineDecisionRefused {
			admittedCount++
		}
	}
	if admittedCount != 1 {
		t.Fatalf("%d of %d racing executions were admitted, want exactly 1", admittedCount, racers)
	}
}

// lv78 A1b, phase (c): a deadline that passes while the action runs withholds
// the output with the distinct code, so the App reads state again.
func TestAccountOutputIsWithheldWhenTheDeadlinePassesDuringTheCall(t *testing.T) {
	call := accountCalls()["mls_device_revoke_sign"]
	f := newOnlineFixture(t)
	d := f.decideAccount(t, call, f.prepareAccount(t, call))
	ran := false
	restore := setChatOnlineAfterWorkForTesting(func() {
		ran = true
		f.clock.advance(proto.MLSAccountOnlineDecisionTTLSeconds * time.Second)
	})
	defer restore()
	response := f.executeAccount(call, call.request, d)
	if !ran || response.Success || response.ErrorCode != ErrCodeChatOnlineOutputWithheld || response.Data != nil {
		t.Fatalf("ran=%v, want %s without data, got %+v", ran, ErrCodeChatOnlineOutputWithheld, response)
	}
}
