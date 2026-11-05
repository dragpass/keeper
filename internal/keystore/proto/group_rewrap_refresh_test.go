package proto

import "testing"

func TestMemberKeyRefreshContextsDoNotCrossSourceKinds(t *testing.T) {
	for _, tc := range []struct {
		operation string
		source    string
		allowed   bool
	}{
		{"member_key_refresh_current", "stored_member", true},
		{"member_key_refresh_current", "retained_member", false},
		{"member_key_refresh_retained", "retained_member", true},
		{"member_key_refresh_retained", "stored_member", false},
		{"member_backfill", "stored_member", false},
	} {
		if got := ValidMemberRewrapContext(tc.operation, tc.source); got != tc.allowed {
			t.Errorf("context %s/%s accepted=%t, want %t", tc.operation, tc.source, got, tc.allowed)
		}
	}
}
