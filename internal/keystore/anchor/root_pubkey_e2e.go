//go:build keeper_e2e

package anchor

import "os"

// rootPublicKeyEnvVar lets a test Keeper trust a root key it generated. Only
// a keeper_e2e build reads it; a release build takes the root key from
// -ldflags alone.
const rootPublicKeyEnvVar = "KEEPER_ROOT_PUBLIC_KEY_BASE64"

func rootPublicKeyOverride() string { return os.Getenv(rootPublicKeyEnvVar) }
