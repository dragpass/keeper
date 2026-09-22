//go:build !mls

package main

import "github.com/dragpass/keeper/internal/keystore"

// logMLSLibrary is a no-op in the default build, which does not link the MLS
// library. See mls_linked.go and internal/keystore/mls.
func logMLSLibrary(*keystore.App) {}
