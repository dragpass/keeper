package proto

import (
	"fmt"
	"strings"
)

const (
	CredentialApprovalChallengeVersion = "dp-credential-approval-v1"
	CredentialApprovalDecisionVersion  = "dp-credential-approval-decision-v1"
)

type CredentialApprovalChallenge struct {
	Version         string `json:"version"`
	ApprovalID      string `json:"approval_id"`
	OrgID           string `json:"org_id"`
	EntryID         string `json:"entry_id"`
	RequestedBy     string `json:"requested_by"`
	AIClientName    string `json:"ai_client_name"`
	AIClientVersion string `json:"ai_client_version"`
	MCPTool         string `json:"mcp_tool"`
	TargetHost      string `json:"target_host"`
	TargetPath      string `json:"target_path"`
	Purpose         string `json:"purpose"`
	Method          string `json:"method"`
	ExpiresAt       string `json:"expires_at"`
}

type SignedCredentialApprovalChallenge struct {
	Challenge        CredentialApprovalChallenge `json:"challenge"`
	Signature        string                      `json:"signature"`
	ServerKeyVersion uint                        `json:"server_key_version"`
	SignatureAlg     string                      `json:"signature_alg"`
}

type CredentialApprovalPromptRequest struct {
	Approval SignedCredentialApprovalChallenge `json:"approval"`
}

func (r CredentialApprovalPromptRequest) Validate() error {
	c := r.Approval.Challenge
	if c.Version != CredentialApprovalChallengeVersion {
		return fmt.Errorf("unsupported credential approval challenge version")
	}
	if strings.TrimSpace(c.ApprovalID) == "" || strings.TrimSpace(c.OrgID) == "" ||
		strings.TrimSpace(c.EntryID) == "" || strings.TrimSpace(c.TargetHost) == "" ||
		strings.TrimSpace(c.TargetPath) == "" || strings.TrimSpace(c.Method) == "" ||
		strings.TrimSpace(c.ExpiresAt) == "" {
		return fmt.Errorf("credential approval challenge is incomplete")
	}
	if r.Approval.Signature == "" || r.Approval.ServerKeyVersion == 0 ||
		r.Approval.SignatureAlg != "rsa-pss-sha256" {
		return fmt.Errorf("credential approval server signature is incomplete")
	}
	return nil
}

type CredentialApprovalDecision struct {
	Decision       string `json:"decision"`
	DecidedAt      string `json:"decided_at"`
	ChallengeHash  string `json:"challenge_hash"`
	KeyFingerprint string `json:"key_fingerprint"`
	Signature      string `json:"signature"`
}
