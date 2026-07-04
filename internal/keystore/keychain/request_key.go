package keychain

// request_key.go — per-device Ed25519 request-signing key CRUD.
//
// A slot completely separate from the identity keypair (RSA, keypair.go).
// Used to authenticate request signatures on the general API. The private
// key is stored as base64 of raw 64B (Ed25519 signing key) — no PEM
// conversion, simplicity first.

import "github.com/dragpass/keeper/config"

// SaveRequestSigningPrivateKey stores base64(Ed25519 64B private seed||pub).
func SaveRequestSigningPrivateKey(store SecretStore, base64Priv string) error {
	return store.Set(config.Service, config.DragPassRequestSigningPrivateKey, base64Priv)
}

// GetRequestSigningPrivateKey returns the stored base64 string.
func GetRequestSigningPrivateKey(store SecretStore) (string, error) {
	return store.Get(config.Service, config.DragPassRequestSigningPrivateKey)
}

// DeleteRequestSigningPrivateKey clears the slot. Called from rotation /
// revocation flows.
func DeleteRequestSigningPrivateKey(store SecretStore) error {
	return store.Delete(config.Service, config.DragPassRequestSigningPrivateKey)
}

// SaveRequestSigningPublicKey stores base64(Ed25519 32B public).
func SaveRequestSigningPublicKey(store SecretStore, base64Pub string) error {
	return store.Set(config.Service, config.DragPassRequestSigningPublicKey, base64Pub)
}

// GetRequestSigningPublicKey returns the stored base64 string.
func GetRequestSigningPublicKey(store SecretStore) (string, error) {
	return store.Get(config.Service, config.DragPassRequestSigningPublicKey)
}

// DeleteRequestSigningPublicKey clears the slot.
func DeleteRequestSigningPublicKey(store SecretStore) error {
	return store.Delete(config.Service, config.DragPassRequestSigningPublicKey)
}

// ──────────────────────────────────────────────────────────────────────
// pending slots (rotation prepare/promote/abort).
// ──────────────────────────────────────────────────────────────────────

func SavePendingRequestSigningPrivateKey(store SecretStore, base64Priv string) error {
	return store.Set(config.Service, config.PendingDragPassRequestSigningPrivateKey, base64Priv)
}

func GetPendingRequestSigningPrivateKey(store SecretStore) (string, error) {
	return store.Get(config.Service, config.PendingDragPassRequestSigningPrivateKey)
}

func DeletePendingRequestSigningPrivateKey(store SecretStore) error {
	return store.Delete(config.Service, config.PendingDragPassRequestSigningPrivateKey)
}

func SavePendingRequestSigningPublicKey(store SecretStore, base64Pub string) error {
	return store.Set(config.Service, config.PendingDragPassRequestSigningPublicKey, base64Pub)
}

func GetPendingRequestSigningPublicKey(store SecretStore) (string, error) {
	return store.Get(config.Service, config.PendingDragPassRequestSigningPublicKey)
}

func DeletePendingRequestSigningPublicKey(store SecretStore) error {
	return store.Delete(config.Service, config.PendingDragPassRequestSigningPublicKey)
}
