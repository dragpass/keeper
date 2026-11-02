package proto

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

// Shared with ariadne rotationbaseline (same literals): the record digest and
// the decision canonical string.
func TestChangeCompareVectors(t *testing.T) {
	d := ChangeRecordDigest(bytes.Repeat([]byte{1}, 12), bytes.Repeat([]byte{2}, 81), 3, 7)
	if got := hex.EncodeToString(d[:]); got != changeRecordDigestVector {
		t.Fatalf("record digest %s", got)
	}
	dec := ChangeCompareDecision{
		Challenge: strings.Repeat("Q", 43), AccountID: "11111111-1111-4111-8111-111111111111",
		DeviceID: "22222222-2222-4222-8222-222222222222", TokenID: "33333333-3333-4333-8333-333333333333",
		SessionIssuedAtNanos: 1000000001, OrgID: "44444444-4444-4444-8444-444444444444",
		GroupID: "55555555-5555-4555-8555-555555555555", DekVersion: 7, GrantDigest: strings.Repeat("a", 64),
		EntryID: "66666666-6666-4666-8666-666666666666", RecordDigest: strings.Repeat("b", 64),
		OperationDigest: strings.Repeat("c", 64), IssuedAt: 1000, ExpiresAt: 1010, ServerKeyVersion: 3,
	}
	want := "dragpass.drag.change-compare|1|" + strings.Repeat("Q", 43) +
		"|11111111-1111-4111-8111-111111111111|22222222-2222-4222-8222-222222222222" +
		"|33333333-3333-4333-8333-333333333333|1000000001|44444444-4444-4444-8444-444444444444" +
		"|55555555-5555-4555-8555-555555555555|7|" + strings.Repeat("a", 64) +
		"|66666666-6666-4666-8666-666666666666|" + strings.Repeat("b", 64) + "|" + strings.Repeat("c", 64) + "|1000|1010|3"
	if got := ChangeCompareDecisionCanonical(dec); got != want {
		t.Fatalf("canonical mismatch")
	}
}

const changeRecordDigestVector = "33d1eb44575d2e0a5777541f78b65e65c74be00d0ba5adfe42418a50c8846fa3"
