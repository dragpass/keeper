package proto

import (
	"math"
	"testing"
)

// The API pins the same vector (ariadne
// internal/services/account/mls_online_decision_canonical_test.go); both
// must change together or a decision stops verifying.
func TestMLSAccountOnlineDecisionCanonicalMatchesTheAPIGoldenVector(t *testing.T) {
	d := MLSAccountOnlineDecision{
		Challenge:            "eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHg",
		AccountID:            "11111111-1111-4111-8111-111111111111",
		DeviceID:             "44444444-4444-4444-8444-444444444444",
		TokenID:              "55555555-5555-4555-8555-555555555555",
		SessionIssuedAtNanos: 1788998000123456789,
		Action:               "mls_device_revoke_sign",
		Target:               "device:66666666-6666-4666-8666-666666666666",
		RequestCommitment:    "7777777777777777777777777777777777777777777777777777777777777777",
		IssuedAt:             1788999000,
		ExpiresAt:            1788999010,
		ServerKeyVersion:     1,
		Signature:            "not-signed",
	}
	want := "dragpass.mls.account_online|1" +
		"|43:eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHg" +
		"|36:11111111-1111-4111-8111-111111111111" +
		"|36:44444444-4444-4444-8444-444444444444" +
		"|36:55555555-5555-4555-8555-555555555555" +
		"|19:1788998000123456789" +
		"|22:mls_device_revoke_sign" +
		"|43:device:66666666-6666-4666-8666-666666666666" +
		"|64:7777777777777777777777777777777777777777777777777777777777777777" +
		"|10:1788999000|10:1788999010|1:1"
	if got := MLSAccountOnlineDecisionCanonical(d); got != want {
		t.Fatalf("canonical =\n%q\nwant\n%q", got, want)
	}
}

func TestMLSAccountOnlineDecisionValidateTakesOnlyTheFixedLifetimeANamedVersionAndATarget(t *testing.T) {
	valid := MLSAccountOnlineDecision{
		Challenge:            "eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHg",
		AccountID:            "11111111-1111-4111-8111-111111111111",
		DeviceID:             "44444444-4444-4444-8444-444444444444",
		TokenID:              "55555555-5555-4555-8555-555555555555",
		SessionIssuedAtNanos: 1788998000123456789,
		Action:               "mls_leaf_declare",
		Target:               "device:44444444-4444-4444-8444-444444444444",
		RequestCommitment:    "7777777777777777777777777777777777777777777777777777777777777777",
		IssuedAt:             1788999000,
		ExpiresAt:            1788999010,
		ServerKeyVersion:     1,
		Signature:            "AA==",
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("a well-formed decision: %v", err)
	}
	for name, change := range map[string]func(*MLSAccountOnlineDecision){
		"lifetime 9":          func(d *MLSAccountOnlineDecision) { d.ExpiresAt = d.IssuedAt + 9 },
		"lifetime 11":         func(d *MLSAccountOnlineDecision) { d.ExpiresAt = d.IssuedAt + 11 },
		"version 0":           func(d *MLSAccountOnlineDecision) { d.ServerKeyVersion = 0 },
		"version over uint32": func(d *MLSAccountOnlineDecision) { d.ServerKeyVersion = math.MaxUint32 + 1 },
		"no target":           func(d *MLSAccountOnlineDecision) { d.Target = "" },
		"upper-case account":  func(d *MLSAccountOnlineDecision) { d.AccountID = "AAAAAAAA-1111-4111-8111-111111111111" },
	} {
		t.Run(name, func(t *testing.T) {
			d := valid
			change(&d)
			if err := d.Validate(); err == nil {
				t.Fatal("Validate accepted it")
			}
		})
	}
}

// The two decisions are domain separated: the same fields never yield the
// same signed bytes for a chat decision and an account decision.
func TestMLSAccountOnlineDecisionCanonicalIsDomainSeparatedFromChat(t *testing.T) {
	account := MLSAccountOnlineDecisionCanonical(MLSAccountOnlineDecision{Action: "x"})
	chat := ChatOnlineDecisionCanonical(ChatOnlineDecision{Action: "x"})
	if account == chat || account[:len(MLSAccountOnlineDecisionDomain)] != MLSAccountOnlineDecisionDomain {
		t.Fatalf("account %q chat %q", account, chat)
	}
}
