//go:build darwin

package userpresence

import "testing"

func TestNewPlatformReportsCocoaConfirm(t *testing.T) {
	capabilities := NewPlatform().Capabilities()
	if !capabilities.Available || !capabilities.Confirm {
		t.Fatalf("Cocoa confirm capability missing: %+v", capabilities)
	}
	if !capabilities.PromptSecret || !capabilities.ShowRecoveryKey {
		t.Fatalf("unexpected secret capabilities: %+v", capabilities)
	}
	if capabilities.Backend != "cocoa" {
		t.Fatalf("backend = %q, want cocoa", capabilities.Backend)
	}
}
