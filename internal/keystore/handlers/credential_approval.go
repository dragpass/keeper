package handlers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/userpresence"
)

type credentialApprovalDecisionCanonical struct {
	Version        string `json:"version"`
	ApprovalID     string `json:"approval_id"`
	ChallengeHash  string `json:"challenge_hash"`
	Decision       string `json:"decision"`
	DecidedAt      string `json:"decided_at"`
	KeyFingerprint string `json:"key_fingerprint"`
}

func HandleCredentialApprovalPrompt(
	d Deps,
	req proto.CredentialApprovalPromptRequest,
) proto.BaseResponse {
	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}
	canonicalChallenge, err := json.Marshal(req.Approval.Challenge)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeValidation, "credential approval challenge is invalid")
	}
	if ok, resp := verifyServerSig(
		d,
		string(canonicalChallenge),
		req.Approval.Signature,
		req.Approval.ServerKeyVersion,
		"credential approval challenge",
	); !ok {
		return resp
	}
	expiresAt, err := time.Parse(time.RFC3339, req.Approval.Challenge.ExpiresAt)
	if err != nil || !d.Now().UTC().Before(expiresAt) {
		return errs.CodeResponse(errs.ErrCodeValidation, "credential approval challenge has expired")
	}
	if d.UserPresence == nil || !d.UserPresence.Capabilities().Confirm {
		return errs.CodeResponse(errs.ErrCodeUnsupported, "credential approval confirmation is unavailable")
	}
	c := req.Approval.Challenge
	client := strings.TrimSpace(c.AIClientName)
	if client == "" {
		client = "AI client"
	}
	message := fmt.Sprintf(
		"%s requests %s https://%s%s\nPurpose: %s",
		client, strings.ToUpper(c.Method), c.TargetHost, c.TargetPath, c.Purpose,
	)
	decision, err := d.UserPresence.Confirm(context.Background(), userpresence.ConfirmPrompt{
		Title:       "Approve DragLink use",
		Message:     message,
		ApproveText: "Approve",
		DenyText:    "Deny",
		Timeout:     expiresAt.Sub(d.Now().UTC()),
	})
	if err != nil {
		return authUserPresenceError(err)
	}

	challengeSum := sha256.Sum256(canonicalChallenge)
	decidedAt := d.Now().UTC().Format(time.RFC3339)
	decisionValue := string(decision)
	if decisionValue != string(userpresence.DecisionApprove) &&
		decisionValue != string(userpresence.DecisionDeny) {
		return errs.CodeResponse(errs.ErrCodeValidation, "invalid user presence decision")
	}

	status := HandleRequestKeyStatus(d, proto.RequestKeyStatusRequest{})
	if !status.Success {
		return status
	}
	key, ok := status.Data.(proto.RequestKeyStatusResponseData)
	if !ok || !key.HasActive || key.Fingerprint == "" {
		return errs.CodeResponse(errs.ErrCodeNotFound, "request signing key not found. enroll first")
	}
	decisionCanonical := credentialApprovalDecisionCanonical{
		Version:        proto.CredentialApprovalDecisionVersion,
		ApprovalID:     c.ApprovalID,
		ChallengeHash:  hex.EncodeToString(challengeSum[:]),
		Decision:       decisionValue,
		DecidedAt:      decidedAt,
		KeyFingerprint: key.Fingerprint,
	}
	rawDecision, err := json.Marshal(decisionCanonical)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeInternal, "credential approval decision encode failed")
	}
	signed := signRequestCanonical(d, string(rawDecision))
	if !signed.Success {
		return signed
	}
	signature, ok := signed.Data.(proto.SignRequestResponseData)
	if !ok {
		return errs.CodeResponse(errs.ErrCodeInternal, "credential approval signature response invalid")
	}
	return proto.BaseResponse{Success: true, Data: proto.CredentialApprovalDecision{
		Decision:       decisionValue,
		DecidedAt:      decidedAt,
		ChallengeHash:  decisionCanonical.ChallengeHash,
		KeyFingerprint: key.Fingerprint,
		Signature:      signature.Signature,
	}}
}
