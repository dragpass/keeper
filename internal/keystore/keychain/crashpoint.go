// crashpoint.go — a named point inside save_session_code's promotion where
// the kill harness (internal/keystore/killharness) can stop a real Keeper
// process. Without the keeper_killseam build tag crashAt does nothing and no
// environment variable is read; no release build carries the tag.

package keychain

// CrashSessionCodeAfterPrivateKey — a staged keypair the server's session
// code opened with is being promoted: the private key slot is written, the
// public key and session code slots are not, and the staged slots are still
// there.
const CrashSessionCodeAfterPrivateKey = "session-code.after-private-key"

var crashAt = func(point string) {}
