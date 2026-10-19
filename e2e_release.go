//go:build !keeper_e2e

package main

import (
	"fmt"
	"strings"

	"github.com/dragpass/keeper/internal/keystore"
)

// A build without the keeper_e2e tag has no E2E mode; e2e_mode.go holds it.

// releaseRefusedEnvPrefixes cover every switch only a keeper_e2e build reads:
// the E2E mode itself, the development App origin
// (DRAGPASS_KEEPER_DEV_APP_ORIGIN) and the root key override
// (KEEPER_ROOT_PUBLIC_KEY_BASE64). Prefixes keep the full names out of the
// release binary, which check-release-no-e2e relies on.
var releaseRefusedEnvPrefixes = []string{"KEEPER_E2E_", "DRAGPASS_KEEPER_DEV_", "KEEPER_ROOT_PUBLIC_KEY_"}

func e2eModeEnabled(func(string) string) bool { return false }

// refuseE2EEnvironment stops a release Keeper started with an E2E switch.
// Ignoring the switch would let a test run that picked up a release binary
// write into the developer's real Keychain, or run without the origin or root
// key it expects; refusing makes the mistake loud.
func refuseE2EEnvironment(environ []string) error {
	for _, entry := range environ {
		name, value, _ := strings.Cut(entry, "=")
		if value == "" {
			continue
		}
		for _, prefix := range releaseRefusedEnvPrefixes {
			if strings.HasPrefix(name, prefix) {
				return fmt.Errorf("%s is set, but this Keeper is a release build without E2E support; E2E runs need a build with the keeper_e2e tag", name)
			}
		}
	}
	return nil
}

func configureE2E(*keystore.Deps) func(*keystore.App) { return nil }
