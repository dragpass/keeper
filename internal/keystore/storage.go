package keystore

// storage.go — Thin `*App` method wrappers for ALL Keychain storage
// operations: keypair / device key / session code / pending keypair /
// multi-version server pubkey / Root fingerprint.
//
// The actual SecretStore CRUD bodies live as exported free functions (with
// SecretStore as the first arg) in `internal/keystore/keychain/`. This file
// holds only one kind of thin adapter:
//
//   - `*App` methods — delegate to `keychain.X(a.Store, ...)`. Every
//     caller grabs an App instance (DefaultApp() in production, helpers
//     like newFacadeTestApp in tests) explicitly, so the SecretStore
//     lifecycle is traceable from one place.
//
// The lowercase free-function shims (`saveDeviceKey()`, etc.) that used
// to sit alongside auto-delegated to `DefaultApp()` at call time, which
// bound them to the process-wide singleton and made it impossible to
// tell which store was being used from the call site alone. Callers
// have been cleaned up to delegate via `DefaultApp().X(...)`.
//
// The multi-version server pubkey + Root fingerprint wrappers that used to
// live in server_keys.go are merged into this file. Both follow the same
// thin-wrapper pattern, so it's natural to keep them together.
//
// `ErrServerKeyVersionNotFound` / `ErrNoActiveServerKey` /
// `ErrSecretNotFound` sentinels live in the keychain package and are
// exposed at keystore root as var aliases in `aliases.go` — `errors.Is`
// semantics preserved.

import "github.com/dragpass/keeper/internal/keystore/keychain"

// =====================================================================
// *App method wrappers
// =====================================================================

// Keypair related functions

func (a *App) savePrivateKey(privateKey string) error {
	return keychain.SavePrivateKey(a.Store, privateKey)
}

func (a *App) getPrivateKey() (string, error) {
	return keychain.GetPrivateKey(a.Store)
}

func (a *App) getPublicKey() (string, error) {
	return keychain.GetPublicKey(a.Store)
}

func (a *App) savePublicKey(publicKey string) error {
	return keychain.SavePublicKey(a.Store, publicKey)
}

// Device key related functions

func (a *App) saveDeviceKey(key string) error {
	return keychain.SaveDeviceKey(a.Store, key)
}

func (a *App) getDeviceKey() (string, error) {
	return keychain.GetDeviceKey(a.Store)
}

func (a *App) deleteDeviceKey() error {
	return keychain.DeleteDeviceKey(a.Store)
}

// Session code related functions

func (a *App) saveSessionCode(sessionCode string) error {
	return keychain.SaveSessionCode(a.Store, sessionCode)
}

// Pending keypair related functions

func (a *App) savePendingPrivateKey(privateKey string) error {
	return keychain.SavePendingPrivateKey(a.Store, privateKey)
}

func (a *App) getPendingPrivateKey() (string, error) {
	return keychain.GetPendingPrivateKey(a.Store)
}

func (a *App) savePendingPublicKey(publicKey string) error {
	return keychain.SavePendingPublicKey(a.Store, publicKey)
}

// promotePendingKeypair moves pending keypair to permanent storage.
func (a *App) promotePendingKeypair() (bool, error) {
	return keychain.PromotePendingKeypair(a.Store)
}

// Multi-version server public key + Root fingerprint (was server_keys.go)

// saveServerPublicKeyForVersion stores the version-N PEM in the Keychain.
func (a *App) saveServerPublicKeyForVersion(version uint, pem string) error {
	return keychain.SaveServerPublicKeyForVersion(a.Store, version, pem)
}

// getServerPublicKeyByVersion fetches the version-N PEM from the
// Keychain.
func (a *App) getServerPublicKeyByVersion(version uint) (string, error) {
	return keychain.GetServerPublicKeyByVersion(a.Store, version)
}

// saveActiveServerKeyVersion updates the active-version pointer.
func (a *App) saveActiveServerKeyVersion(version uint) error {
	return keychain.SaveActiveServerKeyVersion(a.Store, version)
}

// getActiveServerKeyVersion returns the current active version number.
// Returns ErrNoActiveServerKey if the pointer is empty.
func (a *App) getActiveServerKeyVersion() (uint, error) {
	return keychain.GetActiveServerKeyVersion(a.Store)
}

// getServerPublicKeyForVersion is the unified entry point for challenge
// verification. version == 0 falls back to active; otherwise uses the
// exact version.
func (a *App) getServerPublicKeyForVersion(version uint) (string, error) {
	return keychain.GetServerPublicKeyForVersion(a.Store, version)
}

// saveRootPublicKeyFingerprint TOFU-pins the Root pubkey fingerprint.
// Empty string is a no-op (Root-less environments).
func (a *App) saveRootPublicKeyFingerprint(fp string) error {
	return keychain.SaveRootPublicKeyFingerprint(a.Store, fp)
}

// getRootPublicKeyFingerprint returns the fingerprint stored in the
// Keychain, or "" if absent.
func (a *App) getRootPublicKeyFingerprint() (string, error) {
	return keychain.GetRootPublicKeyFingerprint(a.Store)
}
