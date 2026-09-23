// mls_key_package.go — mls_key_package_generate: single-use KeyPackages for
// this device's declared leaf.
//
// Contract: dragpass-control-plane
// docs/exec-plans/active/dragpass-chat-v2-mls-integration.md §5.3, §12.2.

package handlers

import (
	"encoding/base64"
	"encoding/json"
	"errors"

	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/mls"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/secure"
)

// HandleMLSKeyPackageGenerate produces `count` KeyPackages, each carrying the
// active leaf declaration in its LeafNode extension, for the caller to upload.
//
// Gated by the conversation-state permit, as the state actions are, and kept
// off the MCP surface. The permit's account must be the one the stored leaf
// key was declared for: a permit for one account must not mint KeyPackages
// that put another account's leaf into groups.
func HandleMLSKeyPackageGenerate(d Deps, payload json.RawMessage) proto.BaseResponse {
	var req proto.MLSKeyPackageGenerateRequest
	if resp, ok := authorizeChatState(d, payload, &req); !ok {
		return resp
	}
	if !mls.Available() {
		return errs.CodeResponse(errs.ErrorCode(proto.ChatMLSErrorCodeCapabilityRequired),
			"this Keeper was built without the MLS library")
	}

	key, found, err := keychain.GetMLSLeafKey(d.Store)
	secure.Zeroize(key.SecretKey)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "mls leaf key record is unreadable")
	}
	if !found {
		return errs.CodeResponse(errs.ErrCodeNotFound, "no mls leaf key; mls_leaf_declare enroll first")
	}
	if key.AccountID != req.Permit.AccountID {
		return chatStateNotAuthorized(d, "leaf account")
	}

	session, err := mls.NewDeviceSession(d.Store)
	switch {
	case errors.Is(err, mls.ErrNoLeafKey), errors.Is(err, mls.ErrNoLeafDeclaration):
		return errs.CodeResponse(errs.ErrCodeNotFound, err.Error())
	case err != nil:
		d.Logger.Println("mls key package generate: the device session could not be opened")
		return errs.CodeResponse(errs.ErrCodeInternal, "mls device session could not be opened")
	}
	defer session.Close()

	packages, err := session.KeyPackages(req.Count)
	if err != nil {
		d.Logger.Println("mls key package generate: key package generation failed")
		return errs.CodeResponse(errs.ErrCodeInternal, "mls key package generation failed")
	}
	out := make([]proto.MLSKeyPackage, 0, len(packages))
	for _, kp := range packages {
		out = append(out, proto.MLSKeyPackage{
			KeyPackageB64: base64.StdEncoding.EncodeToString(kp.Message),
			NotAfter:      kp.NotAfter,
		})
	}
	d.Logger.Printf("mls key package generate successful (%d key packages)", len(out))
	return proto.BaseResponse{Success: true, Data: proto.MLSKeyPackageGenerateResponseData{KeyPackages: out}}
}
