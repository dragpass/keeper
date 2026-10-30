package handlers

import (
	"encoding/json"

	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/onlineauth"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/secure"
)

func GroupOnlineRequired(Deps, json.RawMessage) proto.BaseResponse {
	return proto.BaseResponse{Error: "current online authorization required", ErrorCode: "online_revocation_check_required"}
}

func groupOnlineIdentity(d Deps, req proto.GroupDecryptToClipboardRequest, tokenID string) (onlineauth.GroupIdentity, []byte, bool) {
	if req.Validate() != nil || d.GroupOnline == nil || d.GroupSessions == nil {
		return onlineauth.GroupIdentity{}, nil, false
	}
	binding, found, err := keychain.GetAccountBinding(d.Store)
	if err != nil || !found || binding.SignedOut || binding.AccountID == "" || binding.Generation == 0 {
		return onlineauth.GroupIdentity{}, nil, false
	}
	device, found, err := keychain.GetDeviceID(d.Store)
	if err != nil || !found || !keychain.ValidDeviceID(device) {
		return onlineauth.GroupIdentity{}, nil, false
	}
	label, err := d.GroupSessions.LabelOf(req.GroupHandle)
	if err != nil || (label.GrantPolicy != proto.GrantPolicyLegacy && label.GrantPolicy != proto.GrantPolicyDecryptOnlyV1) {
		return onlineauth.GroupIdentity{}, nil, false
	}
	encoded, err := json.Marshal(req)
	if err != nil {
		return onlineauth.GroupIdentity{}, nil, false
	}
	return onlineauth.GroupIdentity{TokenID: tokenID, AccountID: binding.AccountID, DeviceID: device, OrgID: label.OrgID,
		GroupID: label.GroupID, DEKVersion: label.DekVersion, GrantPolicy: label.GrantPolicy,
		GrantDigest: label.GrantDigest, LocalGeneration: binding.Generation}, encoded, true
}

func HandleGroupOnlinePrepare(d Deps, req proto.GroupOnlinePrepareRequest) proto.BaseResponse {
	if req.Validate() != nil {
		return GroupOnlineRequired(d, nil)
	}
	id, encoded, ok := groupOnlineIdentity(d, req.Request, req.TokenID)
	defer secure.Zeroize(encoded)
	if !ok {
		return GroupOnlineRequired(d, nil)
	}
	challenge, commitment, err := d.GroupOnline.Prepare(proto.ActionGroupDecryptToClipboard, encoded, id)
	if err != nil {
		return GroupOnlineRequired(d, nil)
	}
	return proto.BaseResponse{Success: true, Data: map[string]any{"token_id": req.TokenID, "challenge": challenge, "commitment": commitment,
		"org_id": id.OrgID, "group_id": id.GroupID, "dek_version": id.DEKVersion,
		"grant_policy": id.GrantPolicy, "grant_digest": id.GrantDigest}}
}

// Dispatch already holds requestMu: identity recheck, challenge consumption
// and the clipboard handler cannot interleave with local sign-out or reset.
func HandleGroupOnlineExecute(d Deps, req proto.GroupOnlineExecuteRequest) proto.BaseResponse {
	if req.Validate() != nil {
		return GroupOnlineRequired(d, nil)
	}
	id, encoded, ok := groupOnlineIdentity(d, req.Request, req.TokenID)
	defer secure.Zeroize(encoded)
	if !ok || d.GroupOnline.VerifyAndConsume(req.Decision, proto.ActionGroupDecryptToClipboard, encoded, id) != nil {
		return GroupOnlineRequired(d, nil)
	}
	return HandleGroupDecryptToClipboard(d, req.Request)
}
