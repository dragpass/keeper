//go:build mls

package main

import (
	"github.com/dragpass/keeper/internal/keystore"
	"github.com/dragpass/keeper/internal/keystore/mls"
)

// logMLSLibrary names the MLS library this binary carries.
//
// It also exists to make the library reachable from main. Nothing else in the
// binary imports the mls package yet, and without a reference here the linker
// drops it whole — a size measurement or a startup check would then be
// describing a binary that does not in fact contain what it claims to. Going
// through Version() rather than a constant means the answer comes back across
// the C ABI, so a broken link fails here rather than at the first send.
func logMLSLibrary(app *keystore.App) {
	version, err := mls.Version()
	if err != nil {
		app.Logger.Printf("Warning: MLS library did not answer: %v", err)
		return
	}
	app.Logger.Printf("MLS library linked: %s", version)
}
