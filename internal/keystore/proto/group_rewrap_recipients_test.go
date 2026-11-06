package proto

import "testing"

func TestRewrapRecipientsDigestBindsEveryOrderedTarget(t *testing.T) {
	base := []RewrapRecipientCommitment{
		{Kind: "account", AccountID: "account-a", KeyFingerprint: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
		{Kind: "archive", KeyFingerprint: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"},
	}
	want, err := RewrapRecipientsDigest(base)
	if err != nil {
		t.Fatal(err)
	}
	if want != "b11c6ad78b7aeb4ac7f837a4ee6f2922adfd3a35a13c142a63c2b06d32bfc65d" {
		t.Fatalf("cross-repository recipient digest changed: %s", want)
	}
	variants := [][]RewrapRecipientCommitment{
		{base[1], base[0]},
		{{Kind: "account", AccountID: "account-b", KeyFingerprint: base[0].KeyFingerprint}, base[1]},
		{{Kind: "account", AccountID: base[0].AccountID, KeyFingerprint: base[1].KeyFingerprint}, base[1]},
		{base[0], {Kind: "self", KeyFingerprint: base[1].KeyFingerprint}},
	}
	for _, variant := range variants {
		got, err := RewrapRecipientsDigest(variant)
		if err != nil || got == want {
			t.Fatalf("changed recipient list had digest %q, error %v", got, err)
		}
	}
	if _, err := RewrapRecipientsDigest([]RewrapRecipientCommitment{{Kind: "archive", KeyFingerprint: "invalid"}}); err == nil {
		t.Fatal("invalid fingerprint accepted")
	}
	if _, err := RewrapRecipientsDigest(nil); err == nil {
		t.Fatal("empty recipient list accepted")
	}
}
