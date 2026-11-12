//go:build !keeper_e2e

package anchor

// A release build takes the root key from -ldflags only; root_pubkey_e2e.go
// holds the test override.
func rootPublicKeyOverride() string { return "" }

// UnverifiedServerKeysAllowed is false in a release build: with no root key
// built in, refresh_server_keys installs nothing, because any caller could
// otherwise choose the keys every server-signed decision is verified with.
func UnverifiedServerKeysAllowed() bool { return false }
