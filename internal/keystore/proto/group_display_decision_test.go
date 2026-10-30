package proto

import (
	"strings"
	"testing"
)

func TestCurrentGroupDisplayDecisionCanonicalMatchesAPI(t *testing.T) {
	d := validGroupDisplayDecision()
	want := "dragpass.group.display|1|QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI" +
		"|11111111-1111-4111-8111-111111111111|22222222-2222-4222-8222-222222222222" +
		"|33333333-3333-4333-8333-333333333333|1000000001|44444444-4444-4444-8444-444444444444" +
		"|7|" + strings.Repeat("a", 64) + "|" + strings.Repeat("b", 64) +
		"|" + strings.Repeat("c", 64) + "|1000|1010|3"
	if got := CurrentGroupDisplayDecisionCanonical(d); got != want {
		t.Fatalf("canonical mismatch: got length %d, want %d", len(got), len(want))
	}
}

func validGroupDisplayDecision() CurrentGroupDisplayDecision {
	return CurrentGroupDisplayDecision{
		Challenge:            "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI",
		AccountID:            "11111111-1111-4111-8111-111111111111",
		DeviceID:             "22222222-2222-4222-8222-222222222222",
		TokenID:              "33333333-3333-4333-8333-333333333333",
		SessionIssuedAtNanos: 1000000001,
		GroupID:              "44444444-4444-4444-8444-444444444444",
		DekVersion:           7,
		GrantDigest:          strings.Repeat("a", 64),
		OperationDigest:      strings.Repeat("b", 64),
		FrameKeyDigest:       strings.Repeat("c", 64),
		IssuedAt:             1000, ExpiresAt: 1010, ServerKeyVersion: 3,
		Signature: "aGVsbG8=",
	}
}

func TestCurrentGroupDisplayDecisionRejectsInvalidFields(t *testing.T) {
	good := validGroupDisplayDecision()
	if err := good.Validate(); err != nil {
		t.Fatalf("valid decision refused: %v", err)
	}
	for name, change := range map[string]func(*CurrentGroupDisplayDecision){
		"challenge":        func(d *CurrentGroupDisplayDecision) { d.Challenge = "short" },
		"account":          func(d *CurrentGroupDisplayDecision) { d.AccountID = "not-an-account" },
		"device":           func(d *CurrentGroupDisplayDecision) { d.DeviceID = "not-a-device" },
		"token":            func(d *CurrentGroupDisplayDecision) { d.TokenID = "not-a-token" },
		"session":          func(d *CurrentGroupDisplayDecision) { d.SessionIssuedAtNanos = 0 },
		"group":            func(d *CurrentGroupDisplayDecision) { d.GroupID = "not-a-group" },
		"version":          func(d *CurrentGroupDisplayDecision) { d.DekVersion = 0 },
		"grant digest":     func(d *CurrentGroupDisplayDecision) { d.GrantDigest = strings.Repeat("A", 64) },
		"operation digest": func(d *CurrentGroupDisplayDecision) { d.OperationDigest = "short" },
		"frame digest":     func(d *CurrentGroupDisplayDecision) { d.FrameKeyDigest = "short" },
		"window":           func(d *CurrentGroupDisplayDecision) { d.ExpiresAt = d.IssuedAt + 11 },
		"key version":      func(d *CurrentGroupDisplayDecision) { d.ServerKeyVersion = 0 },
		"signature":        func(d *CurrentGroupDisplayDecision) { d.Signature = "not base64" },
	} {
		t.Run(name, func(t *testing.T) {
			bad := good
			change(&bad)
			if err := bad.Validate(); err == nil {
				t.Fatal("invalid decision accepted")
			}
		})
	}
}
