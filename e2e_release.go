//go:build !keeper_e2e

package main

import (
	"fmt"
	"strings"

	"github.com/dragpass/keeper/internal/keystore"
)

// A build without the keeper_e2e tag has no E2E mode; e2e_mode.go holds it.

// e2eEnvPrefix covers every E2E switch a keeper_e2e build reads.
const e2eEnvPrefix = "KEEPER_E2E_"

func e2eModeEnabled(func(string) string) bool { return false }

// refuseE2EEnvironment stops a release Keeper started with an E2E switch.
// Ignoring the switch would let a test run that picked up a release binary
// write into the developer's real Keychain; refusing makes the mistake loud.
func refuseE2EEnvironment(environ []string) error {
	for _, entry := range environ {
		name, value, _ := strings.Cut(entry, "=")
		if strings.HasPrefix(name, e2eEnvPrefix) && value != "" {
			return fmt.Errorf("%s is set, but this Keeper is a release build without E2E support; E2E runs need a build with the keeper_e2e tag", name)
		}
	}
	return nil
}

func configureE2E(*keystore.Deps) func(*keystore.App) { return nil }
