//go:build !keeper_e2e

package main

import (
	"strings"
	"testing"
)

// A release build has no E2E mode: every KEEPER_E2E_* variable, and every
// variable that would widen whom Keeper trusts (a dev App origin, a root key
// from the environment), stops the process instead of being silently ignored.
func TestReleaseBuildRefusesE2EEnvironment(t *testing.T) {
	for _, entry := range []string{
		"KEEPER_E2E_MODE=1",
		"KEEPER_E2E_KEYRING_FILE=/tmp/keyring.json",
		"KEEPER_E2E_OS_CLIPBOARD=1",
		"DRAGPASS_KEEPER_DEV_APP_ORIGIN=http://localhost:5174",
		"KEEPER_ROOT_PUBLIC_KEY_BASE64=cm9vdA==",
	} {
		err := refuseE2EEnvironment([]string{"HOME=/home/user", entry})
		name, _, _ := strings.Cut(entry, "=")
		if err == nil || !strings.Contains(err.Error(), name) {
			t.Fatalf("%s: want a refusal naming the variable, got %v", entry, err)
		}
	}
	if err := refuseE2EEnvironment([]string{"HOME=/home/user", "KEEPER_E2E_MODE="}); err != nil {
		t.Fatalf("an empty variable is unset: %v", err)
	}
}

func TestReleaseBuildNeverEntersE2EMode(t *testing.T) {
	getenv := func(string) string { return "1" }
	if e2eModeEnabled(getenv) {
		t.Fatal("a release build must not have an E2E mode")
	}
	if !localRPCEnabled(getenv) {
		t.Fatal("a release Keeper must take part in the shared local owner")
	}
}
