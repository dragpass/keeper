//go:build keeper_e2e

package main

import (
	"testing"

	"github.com/dragpass/keeper/internal/keystore/localsecret"
)

func TestE2EBuildAcceptsE2EEnvironment(t *testing.T) {
	if err := refuseE2EEnvironment([]string{"KEEPER_E2E_MODE=1", "KEEPER_E2E_KEYRING_FILE=/tmp/keyring.json", "DRAGPASS_KEEPER_DEV_APP_ORIGIN=http://localhost:5174", "KEEPER_ROOT_PUBLIC_KEY_BASE64=cm9vdA=="}); err != nil {
		t.Fatalf("a keeper_e2e build must run in E2E mode: %v", err)
	}
}

func TestE2EModeKeepsOffTheSharedLocalAddressUnlessIsolated(t *testing.T) {
	env := map[string]string{}
	getenv := func(key string) string { return env[key] }
	if !localRPCEnabled(getenv) {
		t.Fatal("production Keeper must take part in the shared local owner")
	}
	env[e2eEnvVar] = "1"
	if localRPCEnabled(getenv) {
		t.Fatal("an e2e Keeper with a mock keyring must not proxy to or serve the real local address")
	}
	env[localsecret.DirEnvVar] = t.TempDir()
	if !localRPCEnabled(getenv) {
		t.Fatal("an e2e Keeper with an isolated local secret may use local RPC")
	}
}
