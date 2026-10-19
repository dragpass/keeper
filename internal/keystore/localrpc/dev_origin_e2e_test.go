//go:build keeper_e2e

package localrpc

import (
	"strings"
	"testing"
)

func TestAppOriginsIncludeDevOriginOnlyOnOptIn(t *testing.T) {
	env := map[string]string{}
	getenv := func(key string) string { return env[key] }
	for _, origin := range AppOrigins(getenv) {
		if strings.HasPrefix(origin, "http://") {
			t.Fatalf("production origins include %s", origin)
		}
	}
	env[DevAppOriginEnvVar] = "http://localhost:5174"
	found := false
	for _, origin := range AppOrigins(getenv) {
		found = found || origin == "http://localhost:5174"
	}
	if !found {
		t.Fatal("dev origin missing after opt-in")
	}
}
