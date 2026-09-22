// chat_state_validate_test.go — the conversation-state permit canonical.
//
// The literal below is the whole reason this file exists. ariadne signs these
// bytes and the Keeper verifies them, and the two repositories agree on them
// by pinning the same literal on both sides rather than by both reading the
// same prose. One character of drift and every state action fails with
// CHAT_STATE_NOT_AUTHORIZED, which looks like an authorization bug and is not.

package proto

import (
	"strings"
	"testing"
)

const (
	stateFixtureAccountID = "11111111-1111-4111-8111-111111111111"
	stateFixtureOrgID     = "22222222-2222-4222-8222-222222222222"
	stateFixtureConvID    = "33333333-3333-4333-8333-333333333333"
	stateFixtureIssuedAt  = 1788999000
	stateFixtureExpiresAt = 1788999300 // issued_at + 300

	// stateFixtureCanonicalGolden — the exact bytes ariadne must reproduce.
	// The four watermark values are distinct so that swapping any two of them
	// changes the string, which is what the ordering assertion below rests on.
	stateFixtureCanonicalGolden = "dragpass.chat.state|2|" +
		"11111111-1111-4111-8111-111111111111|" +
		"22222222-2222-4222-8222-222222222222|" +
		"33333333-3333-4333-8333-333333333333|" +
		"7|3|11|42|" +
		"1788999000|1788999300|1"
)

func stateValidPermit() ChatStatePermit {
	return ChatStatePermit{
		AccountID:                stateFixtureAccountID,
		OrgID:                    stateFixtureOrgID,
		ConversationID:           stateFixtureConvID,
		WatermarkEpoch:           7,
		WatermarkLeafIndex:       3,
		WatermarkNextHandshake:   11,
		WatermarkNextApplication: 42,
		IssuedAt:                 stateFixtureIssuedAt,
		ExpiresAt:                stateFixtureExpiresAt,
		ServerKeyVersion:         1,
		Signature:                "aGVsbG8=",
	}
}

// TestChatStatePermitCanonical_GoldenVector — the 12-item signing string on
// fixed inputs. The ariadne signer asserts the same literal.
func TestChatStatePermitCanonical_GoldenVector(t *testing.T) {
	got := ChatStatePermitCanonical(stateValidPermit())
	t.Logf("chat-state-permit canonical (golden): %s", got)
	if got != stateFixtureCanonicalGolden {
		t.Fatalf("permit canonical = %q, want %q", got, stateFixtureCanonicalGolden)
	}
	if strings.Count(got, "|") != 11 {
		t.Fatalf("canonical must have 12 items separated by 11 pipes, got %d", strings.Count(got, "|"))
	}
	if strings.HasSuffix(got, "\n") {
		t.Fatal("canonical must not end with a newline")
	}
}

// TestChatStatePermitCanonical_WatermarkSlotOrder — the four watermark values
// occupy four fixed positions. Two of them exchanged is a different permit
// about a different chain, and the signature has to say so.
func TestChatStatePermitCanonical_WatermarkSlotOrder(t *testing.T) {
	base := stateValidPermit()
	for name, swap := range map[string]func(*ChatStatePermit){
		"epoch / leaf": func(p *ChatStatePermit) {
			p.WatermarkEpoch, p.WatermarkLeafIndex = uint64(p.WatermarkLeafIndex), uint32(p.WatermarkEpoch)
		},
		"epoch / handshake": func(p *ChatStatePermit) {
			p.WatermarkEpoch, p.WatermarkNextHandshake = p.WatermarkNextHandshake, p.WatermarkEpoch
		},
		"epoch / application": func(p *ChatStatePermit) {
			p.WatermarkEpoch, p.WatermarkNextApplication = p.WatermarkNextApplication, p.WatermarkEpoch
		},
		"leaf / handshake": func(p *ChatStatePermit) {
			p.WatermarkLeafIndex, p.WatermarkNextHandshake = uint32(p.WatermarkNextHandshake), uint64(p.WatermarkLeafIndex)
		},
		"leaf / application": func(p *ChatStatePermit) {
			p.WatermarkLeafIndex, p.WatermarkNextApplication = uint32(p.WatermarkNextApplication), uint64(p.WatermarkLeafIndex)
		},
		"handshake / application": func(p *ChatStatePermit) {
			p.WatermarkNextHandshake, p.WatermarkNextApplication = p.WatermarkNextApplication, p.WatermarkNextHandshake
		},
	} {
		swapped := base
		swap(&swapped)
		if ChatStatePermitCanonical(swapped) == stateFixtureCanonicalGolden {
			t.Fatalf("%s swapped produced the same canonical", name)
		}
	}
}

// TestChatStatePermitCanonical_EveryFieldIsSigned — the ten fields a permit
// carries into the canonical each move it. A field that does not is a field
// the server could change after signing.
func TestChatStatePermitCanonical_EveryFieldIsSigned(t *testing.T) {
	base := stateValidPermit()
	for name, mutate := range map[string]func(*ChatStatePermit){
		"account_id":                 func(p *ChatStatePermit) { p.AccountID = stateFixtureOrgID },
		"org_id":                     func(p *ChatStatePermit) { p.OrgID = stateFixtureConvID },
		"conversation_id":            func(p *ChatStatePermit) { p.ConversationID = stateFixtureAccountID },
		"watermark_epoch":            func(p *ChatStatePermit) { p.WatermarkEpoch++ },
		"watermark_leaf_index":       func(p *ChatStatePermit) { p.WatermarkLeafIndex++ },
		"watermark_next_handshake":   func(p *ChatStatePermit) { p.WatermarkNextHandshake++ },
		"watermark_next_application": func(p *ChatStatePermit) { p.WatermarkNextApplication++ },
		"issued_at":                  func(p *ChatStatePermit) { p.IssuedAt++ },
		"expires_at":                 func(p *ChatStatePermit) { p.ExpiresAt++ },
		"server_key_version":         func(p *ChatStatePermit) { p.ServerKeyVersion++ },
	} {
		changed := base
		mutate(&changed)
		if ChatStatePermitCanonical(changed) == stateFixtureCanonicalGolden {
			t.Fatalf("%s left the canonical unchanged", name)
		}
	}

	// The two fixed slots are not reachable through the struct, so they are
	// asserted as the prefix they are.
	if !strings.HasPrefix(stateFixtureCanonicalGolden, ChatStatePermitDomain+"|2|") {
		t.Fatalf("canonical must open with the state domain and schema 2, got %q",
			stateFixtureCanonicalGolden)
	}
	if ChatStatePermitCanonicalVersion != 2 {
		t.Fatalf("canonical version = %d, want 2", ChatStatePermitCanonicalVersion)
	}
}
