package proto

import "testing"

// The API pins the same vector (ariadne
// internal/services/chat/online_decision_canonical_test.go); both must change
// together or a decision stops verifying.
func TestChatOnlineDecisionCanonicalMatchesTheAPIGoldenVector(t *testing.T) {
	d := ChatOnlineDecision{
		Challenge:            "eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHg",
		AccountID:            "11111111-1111-4111-8111-111111111111",
		DeviceID:             "44444444-4444-4444-8444-444444444444",
		TokenID:              "55555555-5555-4555-8555-555555555555",
		SessionIssuedAtNanos: 1788998000123456789,
		Action:               "mls_decrypt_batch_for_app_display",
		OrgID:                "22222222-2222-4222-8222-222222222222",
		ConversationID:       "33333333-3333-4333-8333-333333333333",
		RequestCommitment:    "6666666666666666666666666666666666666666666666666666666666666666",
		IssuedAt:             1788999000,
		ExpiresAt:            1788999010,
		ServerKeyVersion:     1,
		Signature:            "not-signed",
	}
	want := "dragpass.chat.online|1" +
		"|43:eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHg" +
		"|36:11111111-1111-4111-8111-111111111111" +
		"|36:44444444-4444-4444-8444-444444444444" +
		"|36:55555555-5555-4555-8555-555555555555" +
		"|19:1788998000123456789" +
		"|33:mls_decrypt_batch_for_app_display" +
		"|36:22222222-2222-4222-8222-222222222222" +
		"|36:33333333-3333-4333-8333-333333333333" +
		"|64:6666666666666666666666666666666666666666666666666666666666666666" +
		"|10:1788999000|10:1788999010|1:1"
	if got := ChatOnlineDecisionCanonical(d); got != want {
		t.Fatalf("canonical =\n%q\nwant\n%q", got, want)
	}
}
