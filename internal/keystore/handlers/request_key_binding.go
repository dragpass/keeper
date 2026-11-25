package handlers

import (
	"crypto/ed25519"
	"encoding/base64"

	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// HandleRequestKeyBinding authenticates keys already held by this Keeper.
// The paired caller supplies only the login generation it observed.
func HandleRequestKeyBinding(d Deps, request proto.ArchiveLoginScope) proto.BaseResponse {
	if err := request.AppLogin.Validate(); err != nil {
		return errs.Response(err)
	}
	d.ArchiveRequestLogin = &request.AppLogin
	return underStageLock(d.Store, func() proto.BaseResponse {
		owner, err := currentStageOwner(d)
		if err != nil {
			return archiveOwnerRefusal(err)
		}
		pub, err := keychain.GetRequestSigningPublicKey(d.Store)
		if err != nil {
			return errs.CodeResponse(errs.ErrCodeStorageFailure, "request key is unavailable")
		}
		raw, err := base64.StdEncoding.DecodeString(pub)
		if err != nil || len(raw) != ed25519.PublicKeySize || base64.StdEncoding.EncodeToString(raw) != pub {
			return errs.CodeResponse(errs.ErrCodeNotFound, "valid request key required")
		}
		binding := proto.RequestKeyBinding{AccountID: owner.account, DeviceID: owner.device, PublicKey: pub}
		payload, err := binding.Canonical()
		if err != nil {
			return errs.Response(err)
		}
		possession := signRequestCanonical(d, payload)
		if !possession.Success {
			return possession
		}
		proof, err := base64.StdEncoding.DecodeString(possession.Data.(proto.SignRequestResponseData).Signature)
		if err != nil || !ed25519.Verify(raw, []byte(payload), proof) {
			return errs.CodeResponse(errs.ErrCodeCryptoFailure, "request key pair is inconsistent")
		}
		accountKey, err := getPrivateKeySecure(d.Store)
		if err != nil {
			return errs.CodeResponse(errs.ErrCodeNotFound, "account key required")
		}
		defer accountKey.Destroy()
		signature, err := signDataSecure(accountKey, payload)
		if err != nil {
			return errs.CodeResponse(errs.ErrCodeCryptoFailure, "device key binding signing failed")
		}
		current, err := currentStageOwner(d)
		if err != nil {
			return archiveOwnerRefusal(err)
		}
		if current != owner {
			return archiveOwnerRefusal(errArchiveSessionLogin)
		}
		binding.AccountBindingSignature = signature
		return proto.BaseResponse{Success: true, Data: binding}
	})
}
