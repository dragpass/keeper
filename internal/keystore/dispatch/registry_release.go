//go:build !keeper_e2e

package dispatch

// A build without the keeper_e2e tag registers no test-only actions;
// registry_e2e.go holds them.
func e2eActions() map[string]action { return nil }
