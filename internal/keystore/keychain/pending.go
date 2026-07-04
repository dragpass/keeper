package keychain

// pending.go — Pending keypair CRUD + promotion against a SecretStore.
//
// The pending-keypair helper bodies from storage.go moved here as exported
// free functions; the keystore root's thin `*App` wrapper passes `a.Store` as
// the first argument to delegate — zero change to external signatures.
//
// The "pending" slot is the temporary place that holds the new keypair during
// user-key rotation. At promotion time it moves into the active slot.

import "github.com/dragpass/keeper/config"

// SavePendingPrivateKey stores the pending RSA private key PEM.
func SavePendingPrivateKey(store SecretStore, privateKey string) error {
	return store.Set(config.Service, config.PendingDragPassKeeperPrivateKey, privateKey)
}

// GetPendingPrivateKey returns the pending RSA private key PEM.
func GetPendingPrivateKey(store SecretStore) (string, error) {
	return store.Get(config.Service, config.PendingDragPassKeeperPrivateKey)
}

// DeletePendingPrivateKey removes the pending RSA private key PEM.
func DeletePendingPrivateKey(store SecretStore) error {
	return store.Delete(config.Service, config.PendingDragPassKeeperPrivateKey)
}

// SavePendingPublicKey stores the pending RSA public key PEM.
func SavePendingPublicKey(store SecretStore, publicKey string) error {
	return store.Set(config.Service, config.PendingDragPassKeeperPublicKey, publicKey)
}

// GetPendingPublicKey returns the pending RSA public key PEM.
func GetPendingPublicKey(store SecretStore) (string, error) {
	return store.Get(config.Service, config.PendingDragPassKeeperPublicKey)
}

// DeletePendingPublicKey removes the pending RSA public key PEM.
func DeletePendingPublicKey(store SecretStore) error {
	return store.Delete(config.Service, config.PendingDragPassKeeperPublicKey)
}

// PromotePendingKeypair moves the pending keypair to the active slot.
//
// Returns (true, nil) if both pending entries existed and were promoted; the
// pending slots are best-effort cleared after promotion (errors swallowed —
// the active slot is the source of truth from this point on).
//
// Returns (false, nil) if either pending entry is missing (no rotation in
// progress).
//
// Returns (false, err) only on Set failure for the active slot.
func PromotePendingKeypair(store SecretStore) (bool, error) {
	pendingPrivateKey, privErr := GetPendingPrivateKey(store)
	pendingPublicKey, pubErr := GetPendingPublicKey(store)

	// No pending keypair exists.
	if privErr != nil || pubErr != nil {
		return false, nil
	}

	// Promote pending → active.
	if err := SavePrivateKey(store, pendingPrivateKey); err != nil {
		return false, err
	}
	if err := SavePublicKey(store, pendingPublicKey); err != nil {
		return false, err
	}

	// Best-effort cleanup of pending slots.
	_ = DeletePendingPrivateKey(store)
	_ = DeletePendingPublicKey(store)

	return true, nil
}
