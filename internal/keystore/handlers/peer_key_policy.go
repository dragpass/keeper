// peer_key_policy.go — the two strict-mode actions (account key trust v1).
//
// The policy lives in the keyring and nowhere else. There is no server field
// backing it, no sync, and no action that hands it to anything but the
// extension options page that owns the toggle. That is what makes it a
// defence against the server rather than another value the server supplies.
//
// Contract: dragpass-control-plane
// docs/exec-plans/active/account-key-trust-implementation.md §6.5.

package handlers

import (
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// HandlePeerKeyPolicyGet reports the device policy. A device that never set
// one reads the default, which is off.
func HandlePeerKeyPolicyGet(d Deps, req proto.PeerKeyPolicyGetRequest) proto.BaseResponse {
	d.Logger.Println("peer key policy get request processing...")

	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}

	policy, err := keychain.GetPeerKeyPolicy(d.Store)
	if err != nil {
		d.Logger.Printf("peer key policy get error: %v", err)
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "failed to read peer key policy: "+err.Error())
	}

	d.Logger.Printf("peer key policy get successful (require_verified_peers=%t)", policy.RequireVerifiedPeers)
	return proto.BaseResponse{Success: true, Data: proto.PeerKeyPolicyResponseData{
		RequireVerifiedPeers: policy.RequireVerifiedPeers,
	}}
}

// HandlePeerKeyPolicySet stores the device policy and reports what is now in
// the keyring, so the caller renders the stored value rather than its own
// optimistic one.
func HandlePeerKeyPolicySet(d Deps, req proto.PeerKeyPolicySetRequest) proto.BaseResponse {
	d.Logger.Println("peer key policy set request processing...")

	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}

	policy := keychain.PeerKeyPolicy{RequireVerifiedPeers: *req.RequireVerifiedPeers}
	if err := keychain.SavePeerKeyPolicy(d.Store, policy); err != nil {
		d.Logger.Printf("peer key policy set error: %v", err)
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "failed to save peer key policy: "+err.Error())
	}

	d.Logger.Printf("peer key policy set successful (require_verified_peers=%t)", policy.RequireVerifiedPeers)
	return proto.BaseResponse{Success: true, Data: proto.PeerKeyPolicyResponseData{
		RequireVerifiedPeers: policy.RequireVerifiedPeers,
	}}
}
