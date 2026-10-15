package handlers

import (
	"encoding/base64"

	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/recoverykey"
	"github.com/dragpass/keeper/internal/keystore/secure"
)

// HandleOrgEmergencySeedDerive turns the organization emergency recovery code
// into its server seed. Unlike auth_recovery_begin it keeps no handle: there
// is no later step that needs the code inside Keeper, and keeping it would
// make the code something this device holds.
func HandleOrgEmergencySeedDerive(_ Deps, req proto.OrgEmergencySeedDeriveRequest) proto.BaseResponse {
	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}
	code := []byte(req.Code)
	defer secure.Zeroize(code)

	seed, err := recoverykey.DeriveOrgEmergencySeed(code, req.OrgID)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeValidation, "invalid emergency code")
	}
	defer secure.Zeroize(seed)

	return proto.BaseResponse{Success: true, Data: proto.OrgEmergencySeedDeriveResponseData{
		Seed: base64.StdEncoding.EncodeToString(seed),
	}}
}
