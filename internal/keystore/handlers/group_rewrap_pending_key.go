package handlers

import (
	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// HandleDEKRewrapToPendingKey enforces the pending-key target in the action
// itself, including App dispatch calls that did not pass through local RPC.
func HandleDEKRewrapToPendingKey(d Deps, req proto.DEKRewrapForMemberRequest) proto.BaseResponse {
	deny := func() proto.BaseResponse {
		return errs.CodeResponse(errs.ErrCodeNotFound, "Pending key rewrap unavailable")
	}
	if req.Validate() != nil || d.Store == nil || req.OwnerAccountID != "" ||
		req.OtherAccountID != "" || len(req.RotationStatements) != 0 ||
		req.EnrollmentEvidence != nil || req.Decision != nil ||
		req.Operation != "" || req.SourceKind != "" {
		return deny()
	}
	if pendingPrivate, err := keychain.GetPendingPrivateKey(d.Store); err != nil || pendingPrivate == "" {
		return deny()
	}
	pendingPEM, err := keychain.GetPendingPublicKey(d.Store)
	if err != nil || pendingPEM == "" {
		return deny()
	}
	pending, err := crypto.ParsePublicKey(pendingPEM)
	if err != nil {
		return deny()
	}
	target, err := crypto.ParsePublicKey(req.OtherPublicKey)
	if err != nil || !pending.Equal(target) {
		return deny()
	}
	return HandleDEKRewrapForMember(d, req)
}
