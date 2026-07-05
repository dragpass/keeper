// reset_device_identity.go — local self-recovery action.
//
// HandleResetDeviceIdentity wipes this device's account-scoped key material so
// the user can re-enroll after a server-side account/DB reset. Leftover
// Keychain state (active keypair + session code) otherwise makes
// HandleSignAlias refuse signup forever with "device already registered"
// (identity_sign.go guard), and there was no Extension-callable escape short of
// `make refresh` (manual keychain purge).
//
// Security: this is a purely local, destructive action. It never returns key
// material — only the names of the slots actually removed (idempotent: success
// with an empty list when nothing was present). server_public_key is an
// account-independent trust anchor and is intentionally left untouched. Worst
// case after this action is that the device must re-enroll; the account still
// exists on the server and remains reachable via password / recovery key.

package handlers

import (
	"github.com/dragpass/keeper/config"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// resetIdentitySlot pairs a Keychain slot name (reported in the response) with
// its get/delete accessors. get gates whether the slot counts as cleared;
// delete is idempotent at the store layer.
type resetIdentitySlot struct {
	name    string
	present func(keychain.SecretStore) bool
	delete  func(keychain.SecretStore) error
}

// slotPresent reports whether a get accessor resolves to a non-empty value.
func slotPresent(get func(keychain.SecretStore) (string, error)) func(keychain.SecretStore) bool {
	return func(store keychain.SecretStore) bool {
		v, err := get(store)
		return err == nil && v != ""
	}
}

// resetIdentitySlots lists the account-scoped slots wiped by a reset, in a
// stable order: active keypair, pending keypair, session code, device key.
// server_public_key is deliberately absent (account-independent trust anchor).
var resetIdentitySlots = []resetIdentitySlot{
	{config.DragPassKeeperPrivateKey, slotPresent(keychain.GetPrivateKey), keychain.DeletePrivateKey},
	{config.DragPassKeeperPublicKey, slotPresent(keychain.GetPublicKey), keychain.DeletePublicKey},
	{config.PendingDragPassKeeperPrivateKey, slotPresent(keychain.GetPendingPrivateKey), keychain.DeletePendingPrivateKey},
	{config.PendingDragPassKeeperPublicKey, slotPresent(keychain.GetPendingPublicKey), keychain.DeletePendingPublicKey},
	{config.SessionCode, slotPresent(keychain.GetSessionCode), keychain.DeleteSessionCode},
	{config.DeviceKey, slotPresent(keychain.GetDeviceKey), keychain.DeleteDeviceKey},
}

// HandleResetDeviceIdentity wipes this device's account-scoped key material.
func HandleResetDeviceIdentity(d Deps, req proto.ResetDeviceIdentityRequest) proto.BaseResponse {
	d.Logger.Println("reset device identity request processing...")

	// Non-nil so an empty result serializes as `[]`, not `null`.
	cleared := make([]string, 0, len(resetIdentitySlots))
	for _, s := range resetIdentitySlots {
		if !s.present(d.Store) {
			continue
		}
		// Present → delete. A slot that raced away between the presence check
		// and delete is fine (idempotent); the check already gated the list.
		_ = s.delete(d.Store)
		cleared = append(cleared, s.name)
	}

	d.Logger.Printf("reset device identity: cleared %d slot(s)", len(cleared))
	return proto.BaseResponse{Success: true, Data: proto.ResetDeviceIdentityResponseData{Cleared: cleared}}
}
