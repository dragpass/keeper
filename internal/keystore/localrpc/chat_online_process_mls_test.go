//go:build mls && cgo

// chat_online_process_mls_test.go — the online decision gate (lv78 K4) in a
// real Keeper owner process built with the MLS library: the App prepares,
// a stand-in for the API signs the decision with the server key the owner
// pins, and the App executes over real local RPC.

package localrpc

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/dragpass/keeper/internal/keystore"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

const (
	rvTokenID      = "e5555555-5555-4555-8555-555555555555"
	rvSessionStart = int64(1788998000123456789)
)

// rvDecide signs what the API would answer for prepared, shifted by shift
// seconds from now.
func rvDecide(t *testing.T, d *rvDeviceDir, action string, prepared proto.ChatOnlinePrepareResponseData, shift int64) proto.ChatOnlineDecision {
	t.Helper()
	now := time.Now().Unix() + shift
	decision := proto.ChatOnlineDecision{
		Challenge: prepared.Challenge, AccountID: rvAccount, DeviceID: rvDevice,
		TokenID: rvTokenID, SessionIssuedAtNanos: rvSessionStart, Action: action,
		OrgID: rvOrg, ConversationID: rvConv, RequestCommitment: prepared.RequestCommitment,
		IssuedAt: now, ExpiresAt: now + proto.ChatOnlineDecisionTTLSeconds, ServerKeyVersion: 1,
	}
	decision.Signature = d.sign(t, proto.ChatOnlineDecisionCanonical(decision))
	return decision
}

func rvPrepare(t *testing.T, client *testAppClient, action string, request json.RawMessage) (proto.ChatOnlinePrepareResponseData, rvResult) {
	t.Helper()
	result := rvCall(t, client, "/v1/chat/online/prepare", map[string]any{
		"action": action, "request": request, "token_id": rvTokenID,
		"session_issued_at_nanos": "1788998000123456789",
	})
	var prepared proto.ChatOnlinePrepareResponseData
	if result.Success {
		_ = json.Unmarshal(result.Data, &prepared)
	}
	return prepared, result
}

func rvExecute(t *testing.T, client *testAppClient, action string, request json.RawMessage, decision proto.ChatOnlineDecision) rvResult {
	t.Helper()
	return rvCall(t, client, "/v1/chat/online/execute", map[string]any{"action": action, "request": request, "decision": decision})
}

// rvProtected runs one protected action the way the App does: prepare, the
// API's decision, execute. A refused prepare is returned as is.
func rvProtected(t *testing.T, d *rvDeviceDir, client *testAppClient, action string, body any) rvResult {
	t.Helper()
	request, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	prepared, result := rvPrepare(t, client, action, request)
	if !result.Success {
		return result
	}
	return rvExecute(t, client, action, request, rvDecide(t, d, action, prepared, 0))
}

func rvProtectedMust(t *testing.T, d *rvDeviceDir, client *testAppClient, action string, body any, into any) {
	t.Helper()
	result := rvProtected(t, d, client, action, body)
	if !result.Success {
		t.Fatalf("%s: %s (%s)", action, result.Error, result.ErrorCode)
	}
	if into != nil {
		if err := json.Unmarshal(result.Data, into); err != nil {
			t.Fatalf("%s: %v", action, err)
		}
	}
}

// lv78 K4: in a real owner process a protected MLS action runs only with a
// fresh decision for exactly that call; its own route, a replay and an
// expired decision are refused.
func TestOnlineDecisionGatesProtectedMLSWorkInARealKeeper(t *testing.T) {
	server := newRVServer(t)
	bob := bobKeyPackage(t, server)
	d := newRevocationDevice(t, server)
	d.startOwner(t)
	client := d.app(t)
	setUpRoom(t, d, client, bob)

	encrypt := func(id string) json.RawMessage {
		raw, _ := json.Marshal(proto.MLSEncryptRequest{
			Permit: d.permit(t), OrgID: rvOrg, ConversationID: rvConv,
			ClientMessageID: id, ExpectedEpoch: 1,
			PlaintextB64: base64.StdEncoding.EncodeToString([]byte("hello")),
		})
		return raw
	}

	direct := rvCall(t, client, "/v1/chat/"+proto.MLSEncrypt, encrypt("eeeeeeee-eeee-4eee-8eee-200000000001"))
	if direct.Success || direct.ErrorCode != keystore.ErrCodeChatOnlineDecisionRequired {
		t.Fatalf("encrypt on its own route: %+v", direct)
	}

	request := encrypt("eeeeeeee-eeee-4eee-8eee-200000000002")
	prepared, result := rvPrepare(t, client, proto.MLSEncrypt, request)
	if !result.Success {
		t.Fatalf("prepare: %+v", result)
	}
	expired := rvDecide(t, d, proto.MLSEncrypt, prepared, -proto.ChatOnlineDecisionTTLSeconds)
	if refused := rvExecute(t, client, proto.MLSEncrypt, request, expired); refused.Success || refused.ErrorCode != keystore.ErrCodeChatOnlineDecisionRefused {
		t.Fatalf("an expired decision: %+v", refused)
	}
	valid := rvDecide(t, d, proto.MLSEncrypt, prepared, 0)
	sealed := rvExecute(t, client, proto.MLSEncrypt, request, valid)
	var data struct {
		CiphertextB64 string `json:"ciphertext_b64"`
	}
	_ = json.Unmarshal(sealed.Data, &data)
	if !sealed.Success || data.CiphertextB64 == "" {
		t.Fatalf("encrypt with a valid decision: %+v", sealed)
	}
	if replay := rvExecute(t, client, proto.MLSEncrypt, request, valid); replay.Success || replay.ErrorCode != keystore.ErrCodeChatOnlineDecisionRefused {
		t.Fatalf("a replayed decision: %+v", replay)
	}
}
