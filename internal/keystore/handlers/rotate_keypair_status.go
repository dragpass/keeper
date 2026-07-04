// rotate_keypair_status.go — recovery from partial user RSA keypair rotation failures.
//
//   HandleRotateUserKeypairStatus  diagnoses pending slot existence + pending/active public keys
//   HandleRotateUserKeypairAbort   force-discards the pending slot (idempotent)
//
// The normal rotation flow (Prepare + Promote) lives in rotate_keypair.go.

package handlers

import (
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// HandleRotateUserKeypairStatus — stuck-state diagnostic action.
func HandleRotateUserKeypairStatus(d Deps, req proto.RotateUserKeypairStatusRequest) proto.BaseResponse {
	d.Logger.Println("rotate user keypair status request processing...")

	pendingPub, _ := keychain.GetPendingPublicKey(d.Store) // empty string if absent
	activePub, _ := keychain.GetPublicKey(d.Store)         // empty string if absent
	_, hasPriv := getPendingPrivateKeyPresence(d.Store)    // has_pending decided by private-key presence

	hasPending := hasPriv && pendingPub != ""

	return proto.BaseResponse{Success: true, Data: proto.RotateUserKeypairStatusResponseData{
		HasPending:       hasPending,
		PendingPublicKey: pendingPub,
		ActivePublicKey:  activePub,
	}}
}

// HandleRotateUserKeypairAbort — stuck-state cleanup action.
func HandleRotateUserKeypairAbort(d Deps, req proto.RotateUserKeypairAbortRequest) proto.BaseResponse {
	d.Logger.Println("rotate user keypair abort request processing...")

	_, hadPriv := getPendingPrivateKeyPresence(d.Store)
	_, hadPub := getPendingPublicKeyPresence(d.Store)

	// idempotent — missing slot is OK
	_ = keychain.DeletePendingPrivateKey(d.Store)
	_ = keychain.DeletePendingPublicKey(d.Store)

	aborted := hadPriv || hadPub
	if aborted {
		d.Logger.Println("rotate user keypair abort: pending slot cleared")
	} else {
		d.Logger.Println("rotate user keypair abort: no pending slot to clear (no-op)")
	}
	return proto.BaseResponse{Success: true, Data: proto.RotateUserKeypairAbortResponseData{Aborted: aborted}}
}

// getPendingPrivateKeyPresence is a helper that only checks whether the pending private-key slot exists.
func getPendingPrivateKeyPresence(store keychain.SecretStore) (string, bool) {
	v, err := keychain.GetPendingPrivateKey(store)
	if err != nil || v == "" {
		return "", false
	}
	return "", true
}

// getPendingPublicKeyPresence — same pattern (public-key slot).
func getPendingPublicKeyPresence(store keychain.SecretStore) (string, bool) {
	v, err := keychain.GetPendingPublicKey(store)
	if err != nil || v == "" {
		return "", false
	}
	return v, true
}
