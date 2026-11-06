package proto

import (
	"strings"
	"testing"
)

func validGroupRewrapDecision() GroupRewrapDecision {
	return GroupRewrapDecision{
		Challenge:            strings.Repeat("A", 43),
		AccountID:            "11111111-1111-4111-8111-111111111111",
		DeviceID:             "22222222-2222-4222-8222-222222222222",
		TokenID:              "33333333-3333-4333-8333-333333333333",
		SessionIssuedAtNanos: 123,
		Operation:            "member_invite",
		OrgID:                "44444444-4444-4444-8444-444444444444",
		GroupID:              "55555555-5555-4555-8555-555555555555",
		DEKVersion:           2,
		SourceKind:           "stored_member",
		SourceGrantDigest:    strings.Repeat("a", 64),
		SourcePolicy:         GrantPolicyLegacy,
		OutputPolicy:         GrantPolicyLegacy,
		RequestDigest:        strings.Repeat("b", 64),
		RecipientsDigest:     strings.Repeat("c", 64),
		IssuedAt:             100,
		ExpiresAt:            110,
		ServerKeyVersion:     1,
		Signature:            "YWJj",
	}
}

func TestGroupRewrapDecisionValidateRefusesMalformedAuthority(t *testing.T) {
	valid := validGroupRewrapDecision()
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid decision refused: %v", err)
	}
	tests := map[string]func(*GroupRewrapDecision){
		"challenge": func(d *GroupRewrapDecision) { d.Challenge = "invalid" },
		"requester": func(d *GroupRewrapDecision) { d.AccountID = "" },
		"operation": func(d *GroupRewrapDecision) { d.Operation = "member|invite" },
		"source":    func(d *GroupRewrapDecision) { d.SourceGrantDigest = "invalid" },
		"recipient": func(d *GroupRewrapDecision) { d.RecipientsDigest = "invalid" },
		"window":    func(d *GroupRewrapDecision) { d.ExpiresAt++ },
		"signature": func(d *GroupRewrapDecision) { d.Signature = "!" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			decision := valid
			mutate(&decision)
			if err := decision.Validate(); err == nil {
				t.Fatal("malformed signed decision accepted")
			}
		})
	}
}
