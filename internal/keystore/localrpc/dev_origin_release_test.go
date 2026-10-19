//go:build !keeper_e2e

package localrpc

import (
	"slices"
	"testing"
)

// A release Keeper trusts only the deployed App and the Extension, whatever
// its environment says.
func TestReleaseAppOriginsIgnoreTheDevOriginVariable(t *testing.T) {
	getenv := func(key string) string {
		if key == "DRAGPASS_KEEPER_DEV_APP_ORIGIN" {
			return "http://localhost:5174"
		}
		return ""
	}
	want := []string{"https://app.dragpass.io", NativeExtensionOrigin}
	if got := AppOrigins(getenv); !slices.Equal(got, want) {
		t.Fatalf("AppOrigins = %q, want %q", got, want)
	}
}
