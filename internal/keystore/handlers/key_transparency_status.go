package handlers

import (
	"encoding/hex"

	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

func HandleKeyTransparencyStatus(d Deps, _ proto.KeyTransparencyStatusRequest) proto.BaseResponse {
	gate := d.KeyTransparency
	result := proto.KeyTransparencyStatusResponse{
		Configured:           gate.Trust != nil,
		IndependentWitnesses: gate.Trust != nil && gate.Trust.IndependentWitnesses,
	}
	if gate.ConfigErr != nil {
		result.TrustError = proto.KeyTransparencyTrustErrorInvalid
	}
	anchor, found, err := keychain.GetKeyTransparencyCheckpoint(d.Store)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "key transparency status is unavailable")
	}
	if found {
		result.Anchored = true
		result.Origin = anchor.Origin
		result.TreeSize = anchor.Size
		result.RootHash = hex.EncodeToString(anchor.Root)
	}
	return proto.BaseResponse{Success: true, Data: result}
}
