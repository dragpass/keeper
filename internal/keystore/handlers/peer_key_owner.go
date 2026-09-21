// peer_key_owner.go — owner trust-on-first-use for the pin namespace, and the
// one action that clears it (account key trust v1).
//
// A pin lives at `peer-pin:<owner>:<peer>`. The peer half is checked by the
// state machine; the owner half was checked by nothing. It arrives as a
// request field whose original source is the server (`GET /account/me` →
// account id), which makes the adversary the pin defends against the same
// party that picks the namespace the pin is looked up in.
//
// The attack that follows is one lie longer than the one the pin already
// stops. Swap a member's public key *and* report a different account id, and
// the Keeper reads a namespace nothing has ever been written to: every peer is
// a first observation, TOFU allows the wrap, and the fingerprints a human
// verified sit in the old namespace where nothing consults them. `changed`
// never fires. The same lie empties peer_key_pin_list, so the SPA's blocked
// banner loses the data it would have drawn.
//
// requirePeerKeyOwner closes that by recording the first owner id the device
// is ever given and refusing every request that carries a different one.
//
// **What it buys.** A server that switches the id later is refused, and that
// is the case that matters, because the pins worth bypassing were written
// under the first id.
//
// **What it does not buy.** A server that lies consistently from the very
// first use still chooses the namespace. The Keeper has no independent source
// for an account id — the id is a server-side concept and nothing in the
// Keychain derives it — so there is nothing to check a first claim against.
// That residual case is harmless: the namespace is only a label, and the pins
// written inside it are real pins over real peer fingerprints. Substituting a
// peer key under a consistently-lied-about owner still lands on `changed`.
//
// Contract: dragpass-control-plane
// docs/exec-plans/active/account-key-trust-implementation.md §6.1.

package handlers

import (
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// requirePeerKeyOwner checks the request's owner id against the one this
// device recorded, recording it on first ever use. It returns the refusal to
// send and false when the ids disagree.
//
// Every action that takes an `owner_account_id` calls this before touching a
// pin: the two wrap actions (through enforcePeerKeyPins), the four pin
// actions, and peer_key_chain_evaluate. The policy actions do not, because
// they take no owner id — the policy is a device setting.
//
// It runs first in each of those handlers, so a mismatch reads no pin, writes
// no pin, and produces no wrap output. Recording on first use is not a pin
// mutation and happens even when the call goes on to be refused for another
// reason; the alternative would leave the device unbound until some call
// happened to succeed end to end.
func requirePeerKeyOwner(d Deps, ownerAccountID string) (proto.BaseResponse, bool) {
	recorded, found, err := keychain.GetPeerKeyOwner(d.Store)
	if err != nil {
		d.Logger.Printf("peer key owner error: failed to read the recorded owner: %v", err)
		return errs.CodeResponse(
			errs.ErrCodeStorageFailure, "failed to read the recorded peer key owner: "+err.Error(),
		), false
	}

	if !found {
		if err := keychain.SavePeerKeyOwner(d.Store, ownerAccountID, d.Now().Unix()); err != nil {
			d.Logger.Printf("peer key owner error: failed to record the owner: %v", err)
			return errs.CodeResponse(
				errs.ErrCodeStorageFailure, "failed to record the peer key owner: "+err.Error(),
			), false
		}
		d.Logger.Println("peer key owner recorded on first use")
		return proto.BaseResponse{Success: true}, true
	}

	if recorded.AccountID != ownerAccountID {
		// Neither id goes into the message or the log. The caller already
		// knows the one it sent, and the recorded one is what a caller
		// probing for the namespace would want back.
		d.Logger.Println("peer key owner refused: the request names a different owner than this device recorded")
		return proto.BaseResponse{
			Success: false,
			Error: "owner_account_id does not match the account this device recorded; " +
				"no pin was read or changed",
			ErrorCode: string(errs.ErrCodePeerKeyOwnerMismatch),
		}, false
	}

	return proto.BaseResponse{Success: true}, true
}

// HandlePeerKeyOwnerReset forgets the recorded owner so the next request binds
// the device to whoever sends it.
//
// This is the escape hatch for a device two accounts genuinely share. It is
// also, unavoidably, the way to undo the check, which is why the contract puts
// it behind the extension options page and nowhere else: no SPA route, no
// content script, no path a server response can steer. The Keeper cannot
// enforce that — it does not know which of the four surfaces that spawn it is
// on the other end of its stdio loop (docs/security/adr-ratchet-state-storage.md
// §3.1) — so the restriction is a client-side obligation, stated in
// docs/protocol.md and in the action's constant, not a check made here.
//
// Pins survive. A device that changes owners keeps the previous owner's
// records under their own prefix, so signing back in finds the verifications
// that were already made.
func HandlePeerKeyOwnerReset(d Deps, req proto.PeerKeyOwnerResetRequest) proto.BaseResponse {
	d.Logger.Println("peer key owner reset request processing...")

	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}

	reset, err := keychain.DeletePeerKeyOwner(d.Store)
	if err != nil {
		d.Logger.Printf("peer key owner reset error: %v", err)
		return errs.CodeResponse(
			errs.ErrCodeStorageFailure, "failed to clear the recorded peer key owner: "+err.Error(),
		)
	}

	d.Logger.Printf("peer key owner reset successful (reset=%t, pins left in place)", reset)
	return proto.BaseResponse{Success: true, Data: proto.PeerKeyOwnerResetResponseData{Reset: reset}}
}
