// Version (binary version metadata) aliases.
//
// internal/keystore/version.go was moved to internal/keystore/version/ so
// that the binary-version metadata has a clearly-scoped home. Keystore-root
// callers (ping_actions.go) can keep referencing `Version` / `BinaryHash()`
// / `BinaryPath()` without importing the subpackage explicitly. main.go
// continues to call `keystore.LoadBinaryInfo()`.
//
// `BinaryHash` and `BinaryPath` are exposed as **getter functions** rather
// than package-level vars: a simple `var BinaryHash = version.BinaryHash`
// would freeze the value at init time (before LoadBinaryInfo runs), so the
// alias must indirect through a func that reads the current subpackage var.

package keystore

import "github.com/dragpass/keeper/internal/keystore/version"

// Version is the keeper binary version constant. Echoed in HandlePing
// responses so the Extension can enforce MIN_KEEPER_VERSION.
const Version = version.Version

// BinaryHash returns the SHA-256 hex of the running keeper binary,
// populated by LoadBinaryInfo. Empty string until LoadBinaryInfo runs.
func BinaryHash() string { return version.BinaryHash }

// BinaryPath returns the absolute path of the running keeper binary,
// populated by LoadBinaryInfo. Empty string until LoadBinaryInfo runs.
func BinaryPath() string { return version.BinaryPath }

// LoadBinaryInfo loads the running binary's path and SHA-256 into the
// version subpackage's vars. Called once from main.go at startup.
var LoadBinaryInfo = version.LoadBinaryInfo
