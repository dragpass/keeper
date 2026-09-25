// chat_state_validate_test.go — the conversation-state permit canonical.
//
// The literal below is the whole reason this file exists. ariadne signs these
// bytes and the Keeper verifies them, and the two repositories agree on them
// by pinning the same literal on both sides rather than by both reading the
// same prose. One character of drift and every state action fails with
// CHAT_STATE_NOT_AUTHORIZED, which looks like an authorization bug and is not.

package proto

import (
	"fmt"
	"strings"
	"testing"
)

const (
	stateFixtureAccountID = "11111111-1111-4111-8111-111111111111"
	stateFixtureOrgID     = "22222222-2222-4222-8222-222222222222"
	stateFixtureConvID    = "33333333-3333-4333-8333-333333333333"
	stateFixtureIssuedAt  = 1788999000
	stateFixtureExpiresAt = 1788999300 // issued_at + 300

	stateFixtureRemovedA = "55555555-5555-4555-8555-555555555555"
	stateFixtureRemovedB = "66666666-6666-4666-8666-666666666666"

	stateFixtureReplacedAccount = "77777777-7777-4777-8777-777777777777"
	stateFixtureReplacedFP      = "66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925"

	stateFixtureRevokedAccount = "88888888-8888-4888-8888-888888888888"
	stateFixtureRevokedDevice  = "99999999-9999-4999-8999-999999999999"

	// stateFixtureCanonicalGolden — the exact bytes ariadne must reproduce.
	// The four watermark values are distinct so that swapping any two of them
	// changes the string, which is what the ordering assertion below rests on.
	stateFixtureCanonicalGolden = "dragpass.chat.state|5|" +
		"11111111-1111-4111-8111-111111111111|" +
		"22222222-2222-4222-8222-222222222222|" +
		"33333333-3333-4333-8333-333333333333|" +
		"7|3|11|42|" +
		"55555555-5555-4555-8555-555555555555,66666666-6666-4666-8666-666666666666|" +
		"77777777-7777-4777-8777-777777777777:66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925|" +
		"88888888-8888-4888-8888-888888888888:99999999-9999-4999-8999-999999999999|" +
		"1788999000|1788999300|1"

	// stateFixtureCanonicalGoldenNothingPending — the same permit with nothing
	// pending in any list: the three slots are present and empty, so four pipes
	// meet.
	stateFixtureCanonicalGoldenNothingPending = "dragpass.chat.state|5|" +
		"11111111-1111-4111-8111-111111111111|" +
		"22222222-2222-4222-8222-222222222222|" +
		"33333333-3333-4333-8333-333333333333|" +
		"7|3|11|42||||" +
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
		PendingRemovalAccountIDs: []string{stateFixtureRemovedA, stateFixtureRemovedB},
		PendingLeafReplacements: []ChatStateLeafReplacement{
			{AccountID: stateFixtureReplacedAccount, NewSignatureKeyFP: stateFixtureReplacedFP},
		},
		PendingDeviceRevocations: []MLSDeviceRef{
			{AccountID: stateFixtureRevokedAccount, DeviceID: stateFixtureRevokedDevice},
		},
		IssuedAt:         stateFixtureIssuedAt,
		ExpiresAt:        stateFixtureExpiresAt,
		ServerKeyVersion: 1,
		Signature:        "aGVsbG8=",
	}
}

// TestChatStatePermitCanonical_GoldenVector — the 15-item signing string on
// fixed inputs, with both lists filled and with both empty. The ariadne signer
// asserts the same two literals.
func TestChatStatePermitCanonical_GoldenVector(t *testing.T) {
	none := stateValidPermit()
	none.PendingRemovalAccountIDs = []string{}
	none.PendingLeafReplacements = []ChatStateLeafReplacement{}
	none.PendingDeviceRevocations = []MLSDeviceRef{}
	for name, tc := range map[string]struct {
		permit ChatStatePermit
		want   string
	}{
		"both pending": {stateValidPermit(), stateFixtureCanonicalGolden},
		"none pending": {none, stateFixtureCanonicalGoldenNothingPending},
	} {
		got := ChatStatePermitCanonical(tc.permit)
		t.Logf("chat-state-permit canonical (%s): %s", name, got)
		if got != tc.want {
			t.Fatalf("%s: permit canonical = %q, want %q", name, got, tc.want)
		}
		if strings.Count(got, "|") != 14 {
			t.Fatalf("%s: canonical must have 15 items separated by 14 pipes, got %d",
				name, strings.Count(got, "|"))
		}
		if strings.HasSuffix(got, "\n") {
			t.Fatalf("%s: canonical must not end with a newline", name)
		}
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

// TestChatStatePermitCanonical_EveryFieldIsSigned — the twelve fields a permit
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
		"pending_removal_account_ids": func(p *ChatStatePermit) {
			p.PendingRemovalAccountIDs = p.PendingRemovalAccountIDs[:1]
		},
		"pending_leaf_replacements account": func(p *ChatStatePermit) {
			p.PendingLeafReplacements = []ChatStateLeafReplacement{
				{AccountID: stateFixtureRemovedB, NewSignatureKeyFP: stateFixtureReplacedFP},
			}
		},
		"pending_leaf_replacements fingerprint": func(p *ChatStatePermit) {
			p.PendingLeafReplacements = []ChatStateLeafReplacement{
				{AccountID: stateFixtureReplacedAccount, NewSignatureKeyFP: strings.Repeat("a", 64)},
			}
		},
		"pending_leaf_replacements emptied": func(p *ChatStatePermit) {
			p.PendingLeafReplacements = []ChatStateLeafReplacement{}
		},
		"pending_device_revocations device": func(p *ChatStatePermit) {
			p.PendingDeviceRevocations = []MLSDeviceRef{{AccountID: stateFixtureRevokedAccount, DeviceID: stateFixtureRemovedA}}
		},
		"pending_device_revocations emptied": func(p *ChatStatePermit) {
			p.PendingDeviceRevocations = []MLSDeviceRef{}
		},
		"issued_at":          func(p *ChatStatePermit) { p.IssuedAt++ },
		"expires_at":         func(p *ChatStatePermit) { p.ExpiresAt++ },
		"server_key_version": func(p *ChatStatePermit) { p.ServerKeyVersion++ },
	} {
		changed := base
		mutate(&changed)
		if ChatStatePermitCanonical(changed) == stateFixtureCanonicalGolden {
			t.Fatalf("%s left the canonical unchanged", name)
		}
	}

	// The two fixed slots are not reachable through the struct, so they are
	// asserted as the prefix they are.
	if !strings.HasPrefix(stateFixtureCanonicalGolden, ChatStatePermitDomain+"|5|") {
		t.Fatalf("canonical must open with the state domain and schema 5, got %q",
			stateFixtureCanonicalGolden)
	}
	if ChatStatePermitCanonicalVersion != 5 {
		t.Fatalf("canonical version = %d, want 5", ChatStatePermitCanonicalVersion)
	}
}

// TestChatStatePermit_PendingRemovalsAreValidatedNotRepaired — every list the
// canonical would not reproduce exactly is refused. Sorting or de-duplicating
// here would verify a signature over bytes the server never signed.
func TestChatStatePermit_PendingRemovalsAreValidatedNotRepaired(t *testing.T) {
	full := make([]string, 0, ChatStateMaxPendingRemovals)
	for i := 0; i < ChatStateMaxPendingRemovals; i++ {
		full = append(full, fmt.Sprintf("%08x-0000-4000-8000-000000000000", i+1))
	}
	over := append(append([]string(nil), full...), "ffffffff-0000-4000-8000-000000000000")

	for name, tc := range map[string]struct {
		ids []string
		ok  bool
	}{
		"empty":          {[]string{}, true},
		"one":            {[]string{stateFixtureRemovedA}, true},
		"sorted":         {[]string{stateFixtureRemovedA, stateFixtureRemovedB}, true},
		"at the bound":   {full, true},
		"null":           {nil, false},
		"unsorted":       {[]string{stateFixtureRemovedB, stateFixtureRemovedA}, false},
		"duplicated":     {[]string{stateFixtureRemovedA, stateFixtureRemovedA}, false},
		"uppercase":      {[]string{strings.ToUpper("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")}, false},
		"uppercase hex":  {[]string{"5555555A-5555-4555-8555-555555555555"}, false},
		"not a uuid":     {[]string{"55555555"}, false},
		"empty entry":    {[]string{""}, false},
		"nil uuid":       {[]string{"00000000-0000-0000-0000-000000000000"}, false},
		"joined in one":  {[]string{stateFixtureRemovedA + "," + stateFixtureRemovedB}, false},
		"over the bound": {over, false},
	} {
		p := stateValidPermit()
		p.PendingRemovalAccountIDs = tc.ids
		err := p.Validate()
		if tc.ok && err != nil {
			t.Fatalf("%s: refused a valid list: %v", name, err)
		}
		if !tc.ok && err == nil {
			t.Fatalf("%s: accepted a malformed list", name)
		}
	}
}

// TestChatStatePermit_PendingLeafReplacementsAreValidatedNotRepaired — the
// replacement list is held to the removal list's rules, plus one entry per
// account and a lowercase 64-hex fingerprint.
func TestChatStatePermit_PendingLeafReplacementsAreValidatedNotRepaired(t *testing.T) {
	entry := func(account, fp string) ChatStateLeafReplacement {
		return ChatStateLeafReplacement{AccountID: account, NewSignatureKeyFP: fp}
	}
	fp := stateFixtureReplacedFP
	full := make([]ChatStateLeafReplacement, 0, ChatStateMaxPendingLeafReplacements)
	for i := 0; i < ChatStateMaxPendingLeafReplacements; i++ {
		full = append(full, entry(fmt.Sprintf("%08x-0000-4000-8000-000000000000", i+1), fp))
	}
	over := append(append([]ChatStateLeafReplacement(nil), full...),
		entry("ffffffff-0000-4000-8000-000000000000", fp))

	for name, tc := range map[string]struct {
		entries []ChatStateLeafReplacement
		ok      bool
	}{
		"empty":        {[]ChatStateLeafReplacement{}, true},
		"one":          {[]ChatStateLeafReplacement{entry(stateFixtureRemovedA, fp)}, true},
		"sorted":       {[]ChatStateLeafReplacement{entry(stateFixtureRemovedA, fp), entry(stateFixtureRemovedB, fp)}, true},
		"at the bound": {full, true},
		"null":         {nil, false},
		"unsorted": {[]ChatStateLeafReplacement{
			entry(stateFixtureRemovedB, fp), entry(stateFixtureRemovedA, fp),
		}, false},
		"duplicated account": {[]ChatStateLeafReplacement{
			entry(stateFixtureRemovedA, fp), entry(stateFixtureRemovedA, strings.Repeat("b", 64)),
		}, false},
		"duplicated entry": {[]ChatStateLeafReplacement{
			entry(stateFixtureRemovedA, fp), entry(stateFixtureRemovedA, fp),
		}, false},
		"uppercase account":     {[]ChatStateLeafReplacement{entry("AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA", fp)}, false},
		"not a uuid":            {[]ChatStateLeafReplacement{entry("55555555", fp)}, false},
		"nil uuid":              {[]ChatStateLeafReplacement{entry("00000000-0000-0000-0000-000000000000", fp)}, false},
		"empty account":         {[]ChatStateLeafReplacement{entry("", fp)}, false},
		"uppercase fingerprint": {[]ChatStateLeafReplacement{entry(stateFixtureRemovedA, strings.ToUpper(fp))}, false},
		"short fingerprint":     {[]ChatStateLeafReplacement{entry(stateFixtureRemovedA, fp[:63])}, false},
		"long fingerprint":      {[]ChatStateLeafReplacement{entry(stateFixtureRemovedA, fp+"0")}, false},
		"non-hex fingerprint":   {[]ChatStateLeafReplacement{entry(stateFixtureRemovedA, "g"+fp[1:])}, false},
		"empty fingerprint":     {[]ChatStateLeafReplacement{entry(stateFixtureRemovedA, "")}, false},
		"over the bound":        {over, false},
	} {
		p := stateValidPermit()
		p.PendingLeafReplacements = tc.entries
		err := p.Validate()
		if tc.ok && err != nil {
			t.Fatalf("%s: refused a valid list: %v", name, err)
		}
		if !tc.ok && err == nil {
			t.Fatalf("%s: accepted a malformed list", name)
		}
	}
}

// Several entries join with "," in the order Validate required.
func TestChatStatePermitCanonical_SeveralReplacementsJoinInOrder(t *testing.T) {
	p := stateValidPermit()
	p.PendingLeafReplacements = []ChatStateLeafReplacement{
		{AccountID: stateFixtureRemovedA, NewSignatureKeyFP: strings.Repeat("a", 64)},
		{AccountID: stateFixtureRemovedB, NewSignatureKeyFP: strings.Repeat("b", 64)},
	}
	want := "|" + stateFixtureRemovedA + ":" + strings.Repeat("a", 64) + "," +
		stateFixtureRemovedB + ":" + strings.Repeat("b", 64) + "|"
	if got := ChatStatePermitCanonical(p); !strings.Contains(got, want) {
		t.Fatalf("canonical %q does not carry %q", got, want)
	}
}
