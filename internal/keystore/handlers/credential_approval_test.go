package handlers

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/userpresence"
)

type approvalPresence struct {
	userpresence.Unavailable
	decision userpresence.Decision
	calls    int
	prompt   userpresence.ConfirmPrompt
}

func (p *approvalPresence) Capabilities() userpresence.Capabilities {
	return userpresence.Capabilities{Available: true, Confirm: true, Backend: "test"}
}

func (p *approvalPresence) Confirm(_ context.Context, prompt userpresence.ConfirmPrompt) (userpresence.Decision, error) {
	p.calls++
	p.prompt = prompt
	return p.decision, nil
}

func approvalRequest(now time.Time) proto.CredentialApprovalPromptRequest {
	return proto.CredentialApprovalPromptRequest{Approval: proto.SignedCredentialApprovalChallenge{
		Challenge: proto.CredentialApprovalChallenge{
			Version:         proto.CredentialApprovalChallengeVersion,
			ApprovalID:      "11111111-1111-4111-8111-111111111111",
			OrgID:           "22222222-2222-4222-8222-222222222222",
			EntryID:         "33333333-3333-4333-8333-333333333333",
			RequestedBy:     "44444444-4444-4444-8444-444444444444",
			AIClientName:    "Claude Code",
			AIClientVersion: "1.2.3",
			MCPTool:         "use_credential_with_http_request",
			TargetHost:      "api.example.com",
			TargetPath:      "/v1/user",
			Purpose:         "verify account",
			Method:          "GET",
			ExpiresAt:       now.Add(time.Minute).Format(time.RFC3339),
		},
		Signature:        "server-signature",
		ServerKeyVersion: 1,
		SignatureAlg:     "rsa-pss-sha256",
	}}
}

func TestHandleCredentialApprovalPrompt_VerifiesPromptsAndSigns(t *testing.T) {
	now := time.Date(2026, 8, 2, 3, 4, 5, 0, time.UTC)
	deps, _, _ := newTestDeps(t)
	deps.Clock = func() time.Time { return now }
	presence := &approvalPresence{decision: userpresence.DecisionApprove}
	deps.UserPresence = presence
	generated := HandleRequestKeyGenerate(deps, proto.RequestKeyGenerateRequest{})
	if !generated.Success {
		t.Fatalf("generate request key: %s", generated.Error)
	}

	resp := HandleCredentialApprovalPrompt(deps, approvalRequest(now))
	if !resp.Success {
		t.Fatalf("approval prompt: code=%s error=%s", resp.ErrorCode, resp.Error)
	}
	if presence.calls != 1 || !strings.Contains(presence.prompt.Message, "GET https://api.example.com/v1/user") {
		t.Fatalf("unexpected prompt: calls=%d prompt=%+v", presence.calls, presence.prompt)
	}
	decision, ok := resp.Data.(proto.CredentialApprovalDecision)
	if !ok {
		t.Fatalf("unexpected data type %T", resp.Data)
	}
	canonical, err := json.Marshal(credentialApprovalDecisionCanonical{
		Version:        proto.CredentialApprovalDecisionVersion,
		ApprovalID:     approvalRequest(now).Approval.Challenge.ApprovalID,
		ChallengeHash:  decision.ChallengeHash,
		Decision:       decision.Decision,
		DecidedAt:      decision.DecidedAt,
		KeyFingerprint: decision.KeyFingerprint,
	})
	if err != nil {
		t.Fatal(err)
	}
	key := generated.Data.(proto.RequestKeyGenerateResponseData)
	pub, _ := base64.StdEncoding.DecodeString(key.PublicKey)
	sig, _ := base64.StdEncoding.DecodeString(decision.Signature)
	if !ed25519.Verify(ed25519.PublicKey(pub), canonical, sig) {
		t.Fatal("approval decision signature did not verify")
	}
}

func TestHandleCredentialApprovalPrompt_ServerVerificationFailureDoesNotPrompt(t *testing.T) {
	now := time.Now().UTC()
	deps, _, _ := newTestDepsFailVerify(t, errors.New("bad server signature"))
	deps.Clock = func() time.Time { return now }
	presence := &approvalPresence{decision: userpresence.DecisionApprove}
	deps.UserPresence = presence

	resp := HandleCredentialApprovalPrompt(deps, approvalRequest(now))
	if resp.Success || presence.calls != 0 {
		t.Fatalf("verify failure must stop before prompt: resp=%+v calls=%d", resp, presence.calls)
	}
}

func TestHandleSignRequest_RejectsApprovalDecisionNamespace(t *testing.T) {
	deps, _, _ := newTestDeps(t)
	generated := HandleRequestKeyGenerate(deps, proto.RequestKeyGenerateRequest{})
	if !generated.Success {
		t.Fatalf("generate request key: %s", generated.Error)
	}
	resp := HandleSignRequest(deps, proto.SignRequestRequest{CanonicalRequest: `{"version":"dp-credential-approval-decision-v1","approval_id":"forged"}`})
	if resp.Success || resp.ErrorCode != "validation_error" {
		t.Fatalf("generic signer accepted approval decision: %+v", resp)
	}
}

func TestHandleRotateRequestKeyPrepare_RejectsApprovalDecisionNamespace(t *testing.T) {
	deps, _, _ := newTestDeps(t)
	generated := HandleRequestKeyGenerate(deps, proto.RequestKeyGenerateRequest{})
	if !generated.Success {
		t.Fatalf("generate request key: %s", generated.Error)
	}
	resp := HandleRotateRequestKeyPrepare(deps, proto.RotateRequestKeyPrepareRequest{ChallengeToken: `{"version":"dp-credential-approval-decision-v1","approval_id":"forged"}`})
	if resp.Success || resp.ErrorCode != "validation_error" {
		t.Fatalf("rotation signer accepted approval decision: %+v", resp)
	}
}
