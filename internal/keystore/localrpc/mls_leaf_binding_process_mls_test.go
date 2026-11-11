//go:build mls && cgo

// mls_leaf_binding_process_mls_test.go — lv78 in a real Keeper owner
// process built with the MLS library: a held handover decision does not
// survive a leaf replaced within the same sign-in, and mls_leaf_status and
// mls_leaf_abort are bound to the current sign-in and the named pending leaf.

package localrpc

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/dragpass/keeper/internal/keystore"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

const rvTakeover = "f1111111-6666-4666-8666-666666666666"

func rvLeafStatus(t *testing.T, client *testAppClient, account string) (proto.MLSLeafStatusResponseData, rvResult) {
	t.Helper()
	result := rvCall(t, client, "/v1/chat/"+proto.ActionMLSLeafStatus, map[string]any{"account_id": account})
	var status proto.MLSLeafStatusResponseData
	if result.Success {
		_ = json.Unmarshal(result.Data, &status)
	}
	return status, result
}

// rvEnroll declares and promotes a leaf through account decisions and
// returns its fingerprint.
func rvEnroll(t *testing.T, d *rvDeviceDir, client *testAppClient, reason string) string {
	t.Helper()
	declare := leafDeclaration(d, t, rvAccount, rvDevice)
	declare.Reason = reason
	var declared proto.MLSLeafDeclareResponseData
	rvAccountMust(t, d, client, rvAccount, rvDevice, proto.ActionMLSLeafDeclare, declare, &declared)
	rvAccountMust(t, d, client, rvAccount, rvDevice, proto.ActionMLSLeafPromote, d.promotion(t, declared), nil)
	return declared.SignatureKeyFingerprint
}

func TestLeafBindingInARealKeeper(t *testing.T) {
	server := newRVServer(t)
	d := newRevocationDevice(t, server)
	d.startOwner(t)
	client := d.app(t)
	rvMust(t, client, "/v1/auth/login/ensure-request-key", map[string]any{}, nil)
	if claim, err := client.claim(routeHolder); err != nil || !claim.Success || client.epoch == "" {
		t.Fatalf("claim: %+v %v", claim, err)
	}
	rvSignIn(t, client, rvAccount, rvDevice)
	first := rvEnroll(t, d, client, proto.MLSLeafReasonEnroll)

	// A handover decision held while the active leaf is replaced within the
	// same sign-in signs nothing.
	handover, _ := json.Marshal(map[string]any{
		"account_id": rvAccount, "old_signature_key_fingerprint": first,
		"new_declaration": map[string]any{
			"account_id": rvAccount, "device_id": "d2222222-2222-4222-8222-222222222222", "signature_key": "AA==",
			"signature_key_fingerprint": strings.Repeat("ab", 32), "not_before": 1, "not_after": 2,
			"reason": "rotate", "signature": "AA==",
		},
		"expires_at": time.Now().Unix() + 300,
	})
	prepared := rvCall(t, client, "/v1/chat/account-online/prepare", map[string]any{
		"action": proto.ActionMLSLeafHandoverSign, "request": json.RawMessage(handover), "token_id": rvTokenID,
		"session_issued_at_nanos": "1788998000123456789", "takeover_request_id": rvTakeover,
	})
	var handoverPrepared proto.MLSAccountOnlinePrepareResponseData
	_ = json.Unmarshal(prepared.Data, &handoverPrepared)
	if !prepared.Success || !strings.Contains(handoverPrepared.Target, "/old_fp:"+first+"/") {
		t.Fatalf("handover prepare: %+v %+v", prepared, handoverPrepared)
	}
	held := rvAccountDecide(t, d, rvAccount, rvDevice, proto.ActionMLSLeafHandoverSign, handoverPrepared, 0)
	second := rvEnroll(t, d, client, proto.MLSLeafReasonRotate)
	if second == first {
		t.Fatal("the rotate did not replace the active leaf")
	}
	refused := rvAccountExecute(t, client, proto.ActionMLSLeafHandoverSign, handover, held)
	if refused.Success || refused.ErrorCode != keystore.ErrCodeChatOnlineDecisionRefused {
		t.Fatalf("a held handover decision after the leaf was replaced: %+v", refused)
	}

	// Status names the sign-in; abort deletes only the named pending leaf of it.
	declare := leafDeclaration(d, t, rvAccount, rvDevice)
	declare.Reason = proto.MLSLeafReasonRotate
	var pending proto.MLSLeafDeclareResponseData
	rvAccountMust(t, d, client, rvAccount, rvDevice, proto.ActionMLSLeafDeclare, declare, &pending)
	status, result := rvLeafStatus(t, client, rvAccount)
	if !result.Success || status.AccountID != rvAccount || status.BindingGeneration == 0 ||
		!status.HasPending || status.PendingFingerprint != pending.SignatureKeyFingerprint || status.ActiveFingerprint != second {
		t.Fatalf("status: %+v %+v", result, status)
	}
	if _, other := rvLeafStatus(t, client, rvBob); other.Success || other.ErrorCode != "CHAT_MLS_LEAF_BINDING_STALE" {
		t.Fatalf("status for another account: %+v", other)
	}
	abort := func(generation uint64, fp string) rvResult {
		return rvCall(t, client, "/v1/chat/"+proto.ActionMLSLeafAbort, map[string]any{
			"account_id": rvAccount, "binding_generation": generation, "pending_signature_key_fingerprint": fp,
		})
	}
	if r := abort(status.BindingGeneration+1, status.PendingFingerprint); r.Success || r.ErrorCode != "CHAT_MLS_LEAF_BINDING_STALE" {
		t.Fatalf("abort for another sign-in: %+v", r)
	}
	if r := abort(status.BindingGeneration, second); r.Success || r.ErrorCode != "CHAT_MLS_LEAF_PENDING_CHANGED" {
		t.Fatalf("abort naming the active leaf: %+v", r)
	}
	if r := abort(status.BindingGeneration, status.PendingFingerprint); !r.Success {
		t.Fatalf("abort of the named pending leaf: %+v", r)
	}
	after, result := rvLeafStatus(t, client, rvAccount)
	if !result.Success || after.HasPending || after.ActiveFingerprint != second {
		t.Fatalf("status after the abort: %+v %+v", result, after)
	}
}
