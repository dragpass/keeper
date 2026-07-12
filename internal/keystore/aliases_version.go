// Version (binary version metadata) aliases.
//
// internal/keystore/version.go was moved to internal/keystore/version/ so
// that the binary-version metadata has a clearly-scoped home. Keystore-root
// callers can keep referencing `Version` without importing the subpackage
// explicitly. main.go continues to call `keystore.LoadBinaryInfo()`.

package keystore

import "github.com/dragpass/keeper/internal/keystore/version"

// Version is the keeper binary version constant. Echoed in HandlePing
// responses so the Extension can enforce MIN_KEEPER_VERSION.
const Version = version.Version

// LoadBinaryInfo loads the running binary's path and SHA-256 into the
// version subpackage's vars. Called once from main.go at startup.
var LoadBinaryInfo = version.LoadBinaryInfo
