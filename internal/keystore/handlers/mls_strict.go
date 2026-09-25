// mls_strict.go — the device's strict policy (require_verified_peers) applied
// to chat (0.0.55, design §0.3 policy 3, Q8 (a) + (ii)).
//
// The toggle is the one the wrap actions already read (§6.5 of the account key
// trust contract): device-local, set only from the extension options page,
// never read or written by the server. In chat it means, when on:
//
//	local Add / Join     refused while any other account the operation brings
//	                     in, or the joined tree holds, is not verified
//	send                 refused while the confirmed tree holds another
//	                     account that is not verified (no pin counts as not
//	                     verified); the refusal names them
//	reading              always allowed
//	a received Commit    never refused: refusing one would fork this device
//	                     off the group. It is applied, and sending is then
//	                     refused by the rule above until the member is
//	                     verified or removed.
//
// `changed` is refused whatever the policy says, by the leaf verifier.
// Setting the policy from an organization is future work (Q8 (c) needs a
// signed org policy first).

package handlers

import (
	"errors"
	"slices"

	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/mls"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// MLSPeerUnverifiedError is a strict refusal: the accounts it would bring in
// or send to that no person here verified, sorted.
type MLSPeerUnverifiedError struct {
	AccountIDs []string
}

func (e *MLSPeerUnverifiedError) Error() string {
	return "the strict policy refuses an account whose key has not been verified"
}

var errPolicyUnreadable = errors.New("the peer key policy is unreadable")

// requireVerifiedPeers reads the device policy. An unreadable record is an
// error, never the default: the default is off, and falling back to it would
// relax the one setting the user turned on.
func requireVerifiedPeers(d Deps) (bool, error) {
	policy, err := keychain.GetPeerKeyPolicy(d.Store)
	if err != nil {
		return false, errPolicyUnreadable
	}
	return policy.RequireVerifiedPeers, nil
}

// unverifiedMembers is every other account in leaves whose pin is not
// verified, a missing pin included.
func unverifiedMembers(d Deps, owner string, leaves []mls.Leaf) ([]string, error) {
	trust, err := MLSMemberTrust(d, owner, leaves)
	if err != nil {
		return nil, err
	}
	verified := map[string]bool{}
	for _, t := range trust {
		verified[t.AccountID] = t.State == string(keychain.PeerKeyPinStateVerified)
	}
	var out []string
	for _, leaf := range leaves {
		account, _, err := mls.ParseCredentialIdentity(leaf.Identity)
		if err != nil {
			return nil, err
		}
		if account != owner && !verified[account] && !slices.Contains(out, account) {
			out = append(out, account)
		}
	}
	slices.Sort(out)
	return out, nil
}

// sendAdmission is the chatstate.SendRequest.Admit of a send under the strict
// policy: session is the one the store has just loaded the confirmed group
// state into.
func sendAdmission(d Deps, owner string, session *mls.Session) func() error {
	return func() error {
		leaves, err := session.Roster()
		if err != nil {
			return err
		}
		unverified, err := unverifiedMembers(d, owner, leaves)
		if err != nil {
			return err
		}
		if len(unverified) > 0 {
			return &MLSPeerUnverifiedError{AccountIDs: unverified}
		}
		return nil
	}
}

func peerUnverifiedResponse(d Deps, stage string, e *MLSPeerUnverifiedError) proto.BaseResponse {
	d.Logger.Printf("chat state %s failed: %s", stage, proto.ChatMLSErrorCodePeerUnverified)
	return proto.BaseResponse{
		Success:   false,
		Error:     "this device requires verified peers and a member's key has not been verified; nothing was built, joined or sent",
		ErrorCode: proto.ChatMLSErrorCodePeerUnverified,
		Data:      proto.MLSPeerUnverifiedData{UnverifiedAccountIDs: e.AccountIDs},
	}
}
