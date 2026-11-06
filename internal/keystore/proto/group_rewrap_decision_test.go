package proto

import "testing"

func TestGroupRewrapDecisionCanonicalBindsSourceRequesterAndRecipients(t *testing.T) {
	d := GroupRewrapDecision{
		Challenge: "challenge", AccountID: "account", DeviceID: "device",
		TokenID: "token", SessionIssuedAtNanos: 123, Operation: "member_invite",
		OrgID: "org", GroupID: "group", DEKVersion: 4,
		SourceKind: "stored_member", SourceGrantDigest: "source",
		SourcePolicy: "legacy", OutputPolicy: "legacy", RequestDigest: "request",
		RecipientsDigest: "recipients", IssuedAt: 100, ExpiresAt: 110,
		ServerKeyVersion: 3, Signature: "signature",
	}
	want := "dragpass.group.rewrap|1|9:challenge|7:account|6:device|5:token|3:123|13:member_invite|3:org|5:group|1:4|13:stored_member|6:source|6:legacy|6:legacy|7:request|10:recipients|3:100|3:110|1:3"
	if got := GroupRewrapDecisionCanonical(d); got != want {
		t.Fatalf("canonical decision = %q, want %q", got, want)
	}
	d.RecipientsDigest = "other-recipient"
	if got := GroupRewrapDecisionCanonical(d); got == want {
		t.Fatal("recipient substitution did not change signed bytes")
	}
	d.RecipientsDigest = "recipients"
	d.Operation = "member|invite"
	withDelimiter := GroupRewrapDecisionCanonical(d)
	d.Operation = "member"
	d.OrgID = "invite|org"
	if GroupRewrapDecisionCanonical(d) == withDelimiter {
		t.Fatal("field delimiter changed boundaries without changing signed bytes")
	}
}
