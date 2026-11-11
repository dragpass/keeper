package dispatch

import (
	"slices"
	"testing"
)

// The set the API issues account-level decisions for (ariadne
// internal/services/account/mls_online_decision.go mlsAccountAuthorities).
// Keeper must require a decision for exactly these. mls_leaf_abort and
// mls_leaf_status have no issuer authority, so they are not in it.
func TestAccountOnlineDecisionActionsMatchTheAPIIssuerSet(t *testing.T) {
	want := []string{
		"mls_device_revoke_sign",
		"mls_key_package_generate",
		"mls_leaf_declare",
		"mls_leaf_handover_sign",
		"mls_leaf_promote",
		"org_member_removal_sign",
	}
	got := AccountOnlineDecisionActions()
	if !slices.Equal(got, want) {
		t.Fatalf("account online decision actions =\n%v\nwant\n%v", got, want)
	}
	for _, action := range want {
		if !AccountOnlineDecisionRequired(action) {
			t.Fatalf("%s does not require an account online decision", action)
		}
		if OnlineDecisionRequired(action) {
			t.Fatalf("%s is in both decision sets", action)
		}
	}
}
