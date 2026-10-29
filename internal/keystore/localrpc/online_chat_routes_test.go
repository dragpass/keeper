package localrpc

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"testing"
	"time"

	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/onlineauth"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

func TestOnlineAppDisplayReachesHandlerOnlyWithServerDecision(t *testing.T) {
	s := newTestServer(t)
	keys := routeKeypair(t)
	if err := keychain.SavePublicKey(s.app.Store, keys.PublicKey); err != nil {
		t.Fatal(err)
	}
	deviceID := routePeer
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&private.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := keychain.SaveServerPublicKeyForVersion(s.app.Store, 3,
		string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}))); err != nil {
		t.Fatal(err)
	}
	session, csrf := openTestSession(t, s)
	generation := loginForFence(t, s, session, csrf, "AAAAAAAAAAAAAAAAAAAAAA", "")
	claim := callFencedRoute(t, s, session, csrf, generation, "", "/v1/chat/runtime/claim",
		map[string]any{"holder_id": routeHolder, "sequence": 1})
	if !claim.Success {
		t.Fatalf("chat lease refused: %s", claim.ErrorCode)
	}
	var lease struct {
		Epoch string `json:"epoch"`
	}
	if err := json.Unmarshal(claim.Data, &lease); err != nil || lease.Epoch == "" {
		t.Fatal("missing lease epoch")
	}
	conv := "33333333-3333-4333-8333-333333333333"
	permit := proto.ChatStatePermit{
		AccountID: routeOwner, OrgID: routePeer, ConversationID: conv,
		PendingRemovalAccountIDs: []string{}, PendingLeafReplacements: []proto.ChatStateLeafReplacement{},
		PendingDeviceRevocations: []proto.MLSDeviceRef{}, IssuedAt: time.Now().Unix(),
		ExpiresAt: time.Now().Add(300 * time.Second).Unix(), ServerKeyVersion: 3,
		Signature: base64.StdEncoding.EncodeToString([]byte("invalid-permit")),
	}
	request := proto.MLSDecryptBatchForAppDisplayRequest{
		Permit: permit, OrgID: routePeer, ConversationID: conv,
		Messages: []proto.MLSDisplayMessage{{Seq: 1, CiphertextB64: base64.StdEncoding.EncodeToString([]byte("ciphertext"))}},
	}
	input := onlineChatInput{Request: request, AppBinding: "app-binding", DeviceID: deviceID}
	prepared := callFencedRoute(t, s, session, csrf, generation, lease.Epoch, "/v1/chat/online/prepare", input)
	if !prepared.Success {
		t.Fatalf("prepare refused: %s", prepared.ErrorCode)
	}
	var challenge struct{ Challenge, Commitment string }
	if err := json.Unmarshal(prepared.Data, &challenge); err != nil || challenge.Challenge == "" {
		t.Fatal("missing challenge")
	}
	now := time.Now()
	decision := onlineauth.Decision{
		Action: proto.MLSDecryptBatchForAppDisplay, Challenge: challenge.Challenge,
		Commitment: challenge.Commitment, AccountID: routeOwner, DeviceID: deviceID,
		SessionStartNanos: 1800000000000000001, AppBinding: input.AppBinding,
		ConversationID: conv, OrgID: routePeer, IssuedAtMs: now.UnixMilli(),
		ExpiresAtMs: now.Add(15 * time.Second).UnixMilli(), ServerKeyVersion: 3,
	}
	digest := sha256.Sum256([]byte(decision.Canonical()))
	signature, err := rsa.SignPSS(rand.Reader, private, crypto.SHA256, digest[:],
		&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256})
	if err != nil {
		t.Fatal(err)
	}
	decision.Signature = base64.StdEncoding.EncodeToString(signature)
	reached := 0
	s.onAction = func(action string, _ []byte, _ proto.BaseResponse) {
		if action == proto.MLSDecryptBatchForAppDisplay {
			reached++
		}
	}
	execute := func(d onlineauth.Decision) routeResult {
		return callFencedRoute(t, s, session, csrf, generation, lease.Epoch,
			"/v1/chat/online/execute", onlineChatExecuteInput{onlineChatInput: input, Decision: d})
	}
	first := execute(decision)
	if first.Success || first.ErrorCode == "online_revocation_check_required" || reached != 1 {
		t.Fatalf("signed decision did not reach the existing permit gate: code %q, reached %d", first.ErrorCode, reached)
	}
	second := execute(decision)
	if second.ErrorCode != "online_revocation_check_required" || reached != 1 {
		t.Fatal("a consumed decision reached protected work twice")
	}

	processRequest := proto.MLSProcessRequest{
		Permit: permit, OrgID: routePeer, ConversationID: conv,
		Seq: 1, Epoch: 1, CommitB64: base64.StdEncoding.EncodeToString([]byte("commit")),
	}
	processInput := map[string]any{
		"request": processRequest, "app_binding": input.AppBinding, "device_id": deviceID,
	}
	processPrepared := callFencedRoute(t, s, session, csrf, generation, lease.Epoch,
		"/v1/chat/online/process/prepare", processInput)
	if !processPrepared.Success {
		t.Fatalf("MLS process prepare refused: %s", processPrepared.ErrorCode)
	}
	var processChallenge struct{ Challenge, Commitment string }
	if err := json.Unmarshal(processPrepared.Data, &processChallenge); err != nil || processChallenge.Challenge == "" {
		t.Fatal("missing MLS process challenge")
	}
	processDecision := onlineauth.Decision{
		Action: proto.MLSProcess, Challenge: processChallenge.Challenge,
		Commitment: processChallenge.Commitment, AccountID: routeOwner, DeviceID: deviceID,
		SessionStartNanos: 1800000000000000001, AppBinding: input.AppBinding,
		ConversationID: conv, OrgID: routePeer, IssuedAtMs: now.UnixMilli(),
		ExpiresAtMs: now.Add(15 * time.Second).UnixMilli(), ServerKeyVersion: 3,
	}
	processDigest := sha256.Sum256([]byte(processDecision.Canonical()))
	processSignature, err := rsa.SignPSS(rand.Reader, private, crypto.SHA256, processDigest[:],
		&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256})
	if err != nil {
		t.Fatal(err)
	}
	processDecision.Signature = base64.StdEncoding.EncodeToString(processSignature)
	processReached := 0
	s.onAction = func(action string, _ []byte, _ proto.BaseResponse) {
		if action == proto.MLSProcess {
			processReached++
		}
	}
	processExecute := callFencedRoute(t, s, session, csrf, generation, lease.Epoch,
		"/v1/chat/online/process/execute", map[string]any{
			"request": processRequest, "app_binding": input.AppBinding,
			"device_id": deviceID, "decision": processDecision,
		})
	if processExecute.Success || processExecute.ErrorCode == "online_revocation_check_required" || processReached != 1 {
		t.Fatalf("signed process decision did not reach the existing permit gate: code %q, reached %d", processExecute.ErrorCode, processReached)
	}
}

func TestOnlineExecuteDecodesExactAppBindingAnd64BitServerSession(t *testing.T) {
	const body = `{"request":{"conversation_id":"conversation"},"app_binding":"binding","decision":{"session_start_nanos":"1800000000000000001"}}`
	var input onlineChatExecuteInput
	if err := decodeStrict(bytes.NewReader([]byte(body)), &input); err != nil {
		t.Fatalf("online execution shape refused: %v", err)
	}
	if input.AppBinding != "binding" || input.Request.ConversationID != "conversation" ||
		input.Decision.SessionStartNanos != 1800000000000000001 {
		t.Fatal("online execution lost its App or server session binding")
	}
}

func TestOldAppDisplayRouteRefusesBeforeProtectedHandler(t *testing.T) {
	server := newTestServer(t)
	session, csrf := openTestSession(t, server)
	code, result, _ := callRoute(t, server, session, csrf,
		"/v1/chat/mls_decrypt_batch_for_app_display", map[string]any{})
	if code != http.StatusOK || result.Success || result.ErrorCode != "online_revocation_check_required" {
		t.Fatalf("old display route admitted or used another gate: HTTP %d, success %v, code %q", code, result.Success, result.ErrorCode)
	}
}

func TestOldAppMLSProcessRouteRefusesBeforeProtectedHandler(t *testing.T) {
	server := newTestServer(t)
	session, csrf := openTestSession(t, server)
	code, result, _ := callRoute(t, server, session, csrf,
		"/v1/chat/mls_process", map[string]any{})
	if code != http.StatusOK || result.Success || result.ErrorCode != "online_revocation_check_required" {
		t.Fatalf("old MLS process route admitted or used another gate: HTTP %d, success %v, code %q", code, result.Success, result.ErrorCode)
	}
}

func TestOldAppMLSGroupCreateRouteRefusesBeforeProtectedHandler(t *testing.T) {
	server := newTestServer(t)
	session, csrf := openTestSession(t, server)
	code, result, _ := callRoute(t, server, session, csrf,
		"/v1/chat/mls_group_create", map[string]any{})
	if code != http.StatusOK || result.Success || result.ErrorCode != "online_revocation_check_required" {
		t.Fatalf("old MLS group-create route admitted or used another gate: HTTP %d, success %v, code %q", code, result.Success, result.ErrorCode)
	}
}

func TestOldAppMLSEncryptRouteRefusesBeforeProtectedHandler(t *testing.T) {
	server := newTestServer(t)
	session, csrf := openTestSession(t, server)
	code, result, _ := callRoute(t, server, session, csrf,
		"/v1/chat/mls_encrypt", map[string]any{})
	if code != http.StatusOK || result.Success || result.ErrorCode != "online_revocation_check_required" {
		t.Fatalf("old MLS encrypt route admitted or used another gate: HTTP %d, success %v, code %q", code, result.Success, result.ErrorCode)
	}
}

func TestOldAppMLSStateMutationRoutesRequireOnlineDecision(t *testing.T) {
	for _, action := range []string{proto.MLSCommitBuild, proto.MLSCommitConfirm, proto.MLSJoin, proto.MLSMarkSent} {
		t.Run(action, func(t *testing.T) {
			server := newTestServer(t)
			session, csrf := openTestSession(t, server)
			code, result, _ := callRoute(t, server, session, csrf, "/v1/chat/"+action, map[string]any{})
			if code != http.StatusOK || result.Success || result.ErrorCode != "online_revocation_check_required" {
				t.Fatalf("old MLS mutation route admitted or used another gate: HTTP %d, success %v, code %q", code, result.Success, result.ErrorCode)
			}
		})
	}
}
