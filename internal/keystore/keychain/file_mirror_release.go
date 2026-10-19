//go:build !keeper_e2e

package keychain

import "github.com/zalando/go-keyring"

// Without the keeper_e2e tag there is no keyring file mirror: these are the
// plain OS keyring calls. file_mirror.go is the E2E version.

func krSet(service, user, value string) error { return keyring.Set(service, user, value) }

func krGet(service, user string) (string, error) { return keyring.Get(service, user) }

func krDelete(service, user string) error { return keyring.Delete(service, user) }
