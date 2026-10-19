//go:build !keeper_e2e

package anchor

// A release build takes the root key from -ldflags only; root_pubkey_e2e.go
// holds the test override.
func rootPublicKeyOverride() string { return "" }
