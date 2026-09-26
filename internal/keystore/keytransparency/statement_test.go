package keytransparency

import (
	"strings"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/proto"
)

func TestEncodeAccountKeyRotationStatementMatchesWireFixture(t *testing.T) {
	statement := proto.KeyRotationStatement{
		AccountID:      "00000000-0000-4000-8000-000000000001",
		OldFingerprint: strings.Repeat("a", 64),
		NewFingerprint: strings.Repeat("b", 64),
		RotatedAt:      1700000000,
		Reason:         proto.KeyRotationReasonVoluntary,
		OldPublicKey:   "b2xk",
		NewPublicKey:   "bmV3",
		OldSignature:   "b2xkLXNpZw==",
		NewSignature:   "bmV3LXNpZw==",
	}

	got, err := EncodeAccountKeyRotationStatement(statement)
	if err != nil {
		t.Fatal(err)
	}
	want := "dragpass.kt.statement|1|account_key_rotation|" +
		"MDAwMDAwMDAtMDAwMC00MDAwLTgwMDAtMDAwMDAwMDAwMDAx|" +
		"YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYQ|" +
		"YmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYg|" +
		"MTcwMDAwMDAwMA|dm9sdW50YXJ5|YjJ4aw|Ym1WMw|YjJ4a0xYTnBadz09|Ym1WM0xYTnBadz09"
	if string(got) != want {
		t.Fatalf("statement = %q, want %q", got, want)
	}
}

func TestEncodeMLSLeafBindingStatementMatchesWireFixture(t *testing.T) {
	declaration := proto.MLSLeafDeclaration{
		AccountID:               "00000000-0000-4000-8000-000000000001",
		DeviceID:                "00000000-0000-4000-8000-000000000002",
		SignatureKey:            "c2lnLWtleQ==",
		SignatureKeyFingerprint: strings.Repeat("a", 64),
		NotBefore:               1700000000,
		NotAfter:                1702592000,
		Reason:                  proto.MLSLeafReasonEnroll,
		Signature:               "c2lnLW1scw==",
	}

	got, err := EncodeMLSLeafBindingStatement(declaration, "pem")
	if err != nil {
		t.Fatal(err)
	}
	want := "dragpass.kt.statement|1|mls_leaf_binding|" +
		"MDAwMDAwMDAtMDAwMC00MDAwLTgwMDAtMDAwMDAwMDAwMDAx|" +
		"MDAwMDAwMDAtMDAwMC00MDAwLTgwMDAtMDAwMDAwMDAwMDAy|" +
		"YzJsbkxXdGxlUT09|" +
		"YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYQ|" +
		"MTcwMDAwMDAwMA|MTcwMjU5MjAwMA|ZW5yb2xs|YzJsbkxXMXNjdz09|cGVt"
	if string(got) != want {
		t.Fatalf("statement = %q, want %q", got, want)
	}
}
