// reset_device_identity.go — local self-recovery action.
//
// HandleResetDeviceIdentity wipes this device's account-scoped key material so
// the user can re-enroll after a server-side account/DB reset. Leftover
// Keychain state (active keypair + session code) otherwise makes
// HandleSignAlias refuse signup forever with "device already registered"
// (identity_sign.go guard), and there was no Extension-callable escape short of
// `make refresh` (manual keychain purge).
//
// It also erases every owner's chat state (chatstate.PurgeAll): the sealed
// files, the anchors, and the seal keys. A reset that spared it would leave the
// one thing on this device that a restored backup can turn into a reused
// (key, nonce) pair, which is the failure the chat state layer cannot take
// back. The purged conversations are not named in `cleared` — that list is the
// Keychain slots, and the chat state is neither one slot nor a fixed number.
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
	"github.com/dragpass/keeper/internal/keystore/chatstate"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/secure"
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
// stable order: active keypair, pending keypair, session code, device key,
// MLS leaf key.
// server_public_key is deliberately absent (account-independent trust anchor).
var resetIdentitySlots = []resetIdentitySlot{
	{config.DragPassKeeperPrivateKey, slotPresent(keychain.GetPrivateKey), keychain.DeletePrivateKey},
	{config.DragPassKeeperPublicKey, slotPresent(keychain.GetPublicKey), keychain.DeletePublicKey},
	{config.PendingDragPassKeeperPrivateKey, slotPresent(keychain.GetPendingPrivateKey), keychain.DeletePendingPrivateKey},
	{config.PendingDragPassKeeperPublicKey, slotPresent(keychain.GetPendingPublicKey), keychain.DeletePendingPublicKey},
	{config.SessionCode, slotPresent(keychain.GetSessionCode), keychain.DeleteSessionCode},
	{config.PendingPersonalKeyBundle, slotPresent(keychain.GetPendingPersonalKeyBundle), keychain.DeletePendingPersonalKeyBundle},
	{config.PersonalDeviceWrappedDEK, slotPresent(keychain.GetPersonalDeviceWrappedDEK), keychain.DeletePersonalDeviceWrappedDEK},
	{config.DeviceKey, slotPresent(keychain.GetDeviceKey), keychain.DeleteDeviceKey},
	// The leaf key's declaration is signed by the account key this reset
	// destroys, and names the account being re-enrolled away from, so the key
	// is account-scoped however device-scoped its record looks.
	{config.MLSLeafSignatureKey, mlsLeafKeyPresent, deleteMLSLeafKey},
}

// An unreadable record counts as present so the reset still removes it.
func mlsLeafKeyPresent(store keychain.SecretStore) bool {
	key, found, err := keychain.GetMLSLeafKey(store)
	secure.Zeroize(key.SecretKey)
	return found || err != nil
}

func deleteMLSLeafKey(store keychain.SecretStore) error {
	_, err := keychain.DeleteMLSLeafKey(store)
	return err
}

// HandleResetDeviceIdentity wipes this device's account-scoped key material.
func HandleResetDeviceIdentity(d Deps, req proto.ResetDeviceIdentityRequest) proto.BaseResponse {
	d.Logger.Println("reset device identity request processing...")

	// Chat state before the slots: a process that dies partway leaves slots a
	// second call clears just as well, while leftover chat state is the
	// entrance for a rewound chain that a reset exists to close.
	//
	// A failure is logged and not returned. Refusing the reset over it would
	// block the re-enrollment this action exists for, and the caller has no
	// remedy to offer beyond calling it again, which it can do anyway.
	if removed, err := chatstate.PurgeAll(d.Store); err != nil {
		d.Logger.Printf("reset device identity: chat state purge incomplete after %d conversation(s)", removed)
	} else {
		d.Logger.Printf("reset device identity: purged chat state for %d conversation(s)", removed)
	}

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
