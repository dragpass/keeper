package proto

import "testing"

// ariadne (account.RecoveryKeyReissueCanonical) pins the same vector; a
// change on one side alone makes every RK24 re-issue fail.
func TestRecoveryKeyReissueCanonicalVector(t *testing.T) {
	const want = "dragpass.recoverykeyreissue|1|1|" +
		"19b25856e1c150ca834cffc8b59b23adbd0ec0389e58eb22b3b64768098d002b|" +
		"adbf45b08ad6468aa147e5b2a23758ef56ab631a2b70ad52501ca358441a34f3"
	if got := RecoveryKeyReissueCanonical(1, "seed", "wrapped"); got != want {
		t.Fatalf("canonical = %q, want %q", got, want)
	}
}
