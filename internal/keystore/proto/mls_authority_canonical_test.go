package proto

import "testing"

// The attestation canonical is signed by ariadne and verified here; the two
// repositories pin the same literal.
func TestMLSCommitAttestationCanonical_GoldenVector(t *testing.T) {
	got := MLSCommitAttestationCanonical(
		"33333333-3333-4333-8333-333333333333", 7,
		"66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925",
		MLSCommitAttestation{
			MemberAccountIDs: []string{
				"11111111-1111-4111-8111-111111111111", "55555555-5555-4555-8555-555555555555",
			},
			ServerKeyVersion: 2,
		})
	want := "dragpass.chat.commit|1|33333333-3333-4333-8333-333333333333|7|" +
		"66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925|" +
		"11111111-1111-4111-8111-111111111111,55555555-5555-4555-8555-555555555555|2"
	if got != want {
		t.Fatalf("attestation canonical = %q, want %q", got, want)
	}
}

func TestMLSCommitAttestation_TheMemberListIsValidatedNotRepaired(t *testing.T) {
	ok := MLSCommitAttestation{
		MemberAccountIDs: []string{"11111111-1111-4111-8111-111111111111"},
		ServerKeyVersion: 1, Signature: "aGVsbG8=",
	}
	if err := ok.Validate("a"); err != nil {
		t.Fatal(err)
	}
	for name, ids := range map[string][]string{
		"empty":    {},
		"unsorted": {"55555555-5555-4555-8555-555555555555", "11111111-1111-4111-8111-111111111111"},
		"dup":      {"11111111-1111-4111-8111-111111111111", "11111111-1111-4111-8111-111111111111"},
		"not uuid": {"alice"},
	} {
		bad := ok
		bad.MemberAccountIDs = ids
		if bad.Validate("a") == nil {
			t.Fatalf("%s member list validated", name)
		}
	}
}
