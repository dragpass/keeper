//go:build mls && cgo

// mls_account_online_process_mls_test.go — the account-level online decision
// gate (lv78 A1b) in a real Keeper owner process built with the MLS library:
// leaf enrolment and KeyPackage generation run only with the API's account
// decision for exactly that call.

package localrpc

import (
	"encoding/json"
	"strconv"
	"testing"
	"time"

	"github.com/dragpass/keeper/internal/keystore"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// rvAccountDecide signs what the API would answer for prepared, as account
// on device, shifted by shift seconds from now.
func rvAccountDecide(t *testing.T, d *rvDeviceDir, account, device, action string, prepared proto.MLSAccountOnlinePrepareResponseData, shift int64) proto.MLSAccountOnlineDecision {
	t.Helper()
	now := time.Now().Unix() + shift
	decision := proto.MLSAccountOnlineDecision{
		Challenge: prepared.Challenge, AccountID: account, DeviceID: device,
		TokenID: rvTokenID, SessionIssuedAtNanos: rvSessionStart, Action: action,
		Target: prepared.Target, RequestCommitment: prepared.RequestCommitment,
		IssuedAt: now, ExpiresAt: now + proto.MLSAccountOnlineDecisionTTLSeconds, ServerKeyVersion: 1,
	}
	decision.Signature = d.sign(t, proto.MLSAccountOnlineDecisionCanonical(decision))
	return decision
}

func rvAccountPrepare(t *testing.T, client *testAppClient, action string, request json.RawMessage) (proto.MLSAccountOnlinePrepareResponseData, rvResult) {
	t.Helper()
	result := rvCall(t, client, "/v1/chat/account-online/prepare", map[string]any{
		"action": action, "request": request, "token_id": rvTokenID,
		"session_issued_at_nanos": "1788998000123456789",
	})
	var prepared proto.MLSAccountOnlinePrepareResponseData
	if result.Success {
		_ = json.Unmarshal(result.Data, &prepared)
	}
	return prepared, result
}

func rvAccountExecute(t *testing.T, client *testAppClient, action string, request json.RawMessage, decision proto.MLSAccountOnlineDecision) rvResult {
	t.Helper()
	return rvCall(t, client, "/v1/chat/account-online/execute", map[string]any{"action": action, "request": request, "decision": decision})
}

// rvAccountMust runs one account-level action the way the App does:
// prepare, the API's account decision, execute.
func rvAccountMust(t *testing.T, d *rvDeviceDir, client *testAppClient, account, device, action string, body any, into any) {
	t.Helper()
	request, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	prepared, result := rvAccountPrepare(t, client, action, request)
	if !result.Success {
		t.Fatalf("%s prepare: %s (%s)", action, result.Error, result.ErrorCode)
	}
	result = rvAccountExecute(t, client, action, request, rvAccountDecide(t, d, account, device, action, prepared, 0))
	if !result.Success {
		t.Fatalf("%s: %s (%s)", action, result.Error, result.ErrorCode)
	}
	if into != nil {
		if err := json.Unmarshal(result.Data, into); err != nil {
			t.Fatalf("%s: %v", action, err)
		}
	}
}

// rvSignIn records the device and the account binding, as the App's sign-in
// does; both the chat and the account decision bind them.
func rvSignIn(t *testing.T, client *testAppClient, account, device string) {
	t.Helper()
	rvMust(t, client, "/v1/device/id", proto.DeviceIDEnsureRequest{CandidateDeviceID: device}, nil)
	rvMust(t, client, "/v1/account/binding", proto.AccountBindingSetRequest{AccountID: account, Alias: "alice"}, nil)
}

// lv78 A1b in a real owner process: leaf declaration, promotion and
// KeyPackage generation run only through the account path with a fresh
// decision; their own routes, an expired decision, a chat-domain signature
// and a replay are refused.
func TestAccountOnlineDecisionGatesLeafAndKeyPackageWorkInARealKeeper(t *testing.T) {
	server := newRVServer(t)
	d := newRevocationDevice(t, server)
	d.startOwner(t)
	client := d.app(t)
	rvMust(t, client, "/v1/auth/login/ensure-request-key", map[string]any{}, nil)
	if claim, err := client.claim(routeHolder); err != nil || !claim.Success || client.epoch == "" {
		t.Fatalf("claim: %+v %v", claim, err)
	}
	rvSignIn(t, client, rvAccount, rvDevice)

	declare := leafDeclaration(d, t, rvAccount, rvDevice)
	direct := rvCall(t, client, "/v1/chat/"+proto.ActionMLSLeafDeclare, declare)
	if direct.Success || direct.ErrorCode != keystore.ErrCodeChatOnlineDecisionRequired {
		t.Fatalf("declare on its own route: %+v", direct)
	}

	request, _ := json.Marshal(declare)
	prepared, result := rvAccountPrepare(t, client, proto.ActionMLSLeafDeclare, request)
	if !result.Success || prepared.Target != "device:"+rvDevice {
		t.Fatalf("prepare: %+v %+v", result, prepared)
	}
	expired := rvAccountDecide(t, d, rvAccount, rvDevice, proto.ActionMLSLeafDeclare, prepared, -proto.MLSAccountOnlineDecisionTTLSeconds)
	if refused := rvAccountExecute(t, client, proto.ActionMLSLeafDeclare, request, expired); refused.Success || refused.ErrorCode != keystore.ErrCodeChatOnlineDecisionRefused {
		t.Fatalf("an expired decision: %+v", refused)
	}
	chatDomain := rvAccountDecide(t, d, rvAccount, rvDevice, proto.ActionMLSLeafDeclare, prepared, 0)
	chatDomain.Signature = d.sign(t, proto.ChatOnlineDecisionDomain+proto.MLSAccountOnlineDecisionCanonical(chatDomain)[len(proto.MLSAccountOnlineDecisionDomain):])
	if refused := rvAccountExecute(t, client, proto.ActionMLSLeafDeclare, request, chatDomain); refused.Success || refused.ErrorCode != keystore.ErrCodeChatOnlineDecisionRefused {
		t.Fatalf("a chat-domain signature: %+v", refused)
	}
	valid := rvAccountDecide(t, d, rvAccount, rvDevice, proto.ActionMLSLeafDeclare, prepared, 0)
	declared := rvAccountExecute(t, client, proto.ActionMLSLeafDeclare, request, valid)
	var declaration proto.MLSLeafDeclareResponseData
	_ = json.Unmarshal(declared.Data, &declaration)
	if !declared.Success || declaration.SignatureKeyFingerprint == "" {
		t.Fatalf("declare with a valid decision: %+v", declared)
	}
	if replay := rvAccountExecute(t, client, proto.ActionMLSLeafDeclare, request, valid); replay.Success || replay.ErrorCode != keystore.ErrCodeChatOnlineDecisionRefused {
		t.Fatalf("a replayed decision: %+v", replay)
	}

	rvAccountMust(t, d, client, rvAccount, rvDevice, proto.ActionMLSLeafPromote, d.promotion(t, declaration), nil)
	challenge := "dragpass.mls.keypackage.challenge|1|" + rvAccount + "|" + rvDevice + "|" + rvNonce + "|" +
		strconv.FormatInt(time.Now().Unix()+proto.MLSKeyPackageChallengeTTLSeconds, 10)
	generate := proto.MLSKeyPackageGenerateRequest{
		ChallengeToken: challenge, ServerSignature: d.sign(t, challenge), ServerKeyVersion: 1,
		AccountID: rvAccount, DeviceID: rvDevice, Count: 1,
	}
	if direct := rvCall(t, client, "/v1/chat/"+proto.MLSKeyPackageGenerate, generate); direct.Success || direct.ErrorCode != keystore.ErrCodeChatOnlineDecisionRequired {
		t.Fatalf("KeyPackages on their own route: %+v", direct)
	}
	var generated proto.MLSKeyPackageGenerateResponseData
	rvAccountMust(t, d, client, rvAccount, rvDevice, proto.MLSKeyPackageGenerate, generate, &generated)
	if len(generated.KeyPackages) != 1 {
		t.Fatalf("KeyPackages with a valid decision: %+v", generated)
	}
}
