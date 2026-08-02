//go:build darwin

package userpresence

import "testing"

func TestNewPlatformReportsRecoveryKeyDisplay(t *testing.T) {
	capabilities := NewPlatform().Capabilities()
	if !capabilities.Available || !capabilities.ShowRecoveryKey {
		t.Fatalf("Cocoa recovery-key display capability missing: %+v", capabilities)
	}
	if capabilities.Backend != "cocoa" {
		t.Fatalf("backend = %q, want cocoa", capabilities.Backend)
	}
}
