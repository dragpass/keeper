package handlers

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"

	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// HandleAuthorizedDEKRewrapForMember is the external execution boundary. The
// dispatcher holds requestMu through this check and the subsequent wrap.
func HandleAuthorizedDEKRewrapForMember(d Deps, req proto.DEKRewrapForMemberRequest) proto.BaseResponse {
	deny := func() proto.BaseResponse {
		return errs.CodeResponse(errs.ErrCodeNotFound, "Group rewrap unavailable")
	}
	if req.Validate() != nil || req.Decision == nil || req.GrantContext == nil ||
		req.OwnerAccountID == "" || req.OtherAccountID == "" ||
		(req.Operation != "member_invite" && req.Operation != "member_add") ||
		req.SourceKind != "stored_member" {
		return deny()
	}
	source, err := base64.StdEncoding.DecodeString(req.WrappedForMeB64)
	if err != nil {
		return deny()
	}
	sourceDigest := sha256.Sum256(source)
	fingerprint, err := crypto.RewrapKeyFingerprint(req.OtherPublicKey)
	if err != nil {
		return deny()
	}
	recipients, err := proto.RewrapRecipientsDigest([]proto.RewrapRecipientCommitment{{
		Kind: "account", AccountID: req.OtherAccountID, KeyFingerprint: fingerprint,
	}})
	if err != nil {
		return deny()
	}
	recipientsBytes, err := hex.DecodeString(recipients)
	if err != nil {
		return deny()
	}
	var recipientsDigest [sha256.Size]byte
	copy(recipientsDigest[:], recipientsBytes)
	requestDigest, err := proto.GroupRewrapMemberRequestDigest(req)
	if err != nil {
		return deny()
	}
	execution := groupRewrapContext{
		operation: req.Operation, orgID: req.GrantContext.OrgID,
		groupID: req.GrantContext.GroupID, dekVersion: req.GrantContext.DekVersion,
		sourceKind: req.SourceKind, sourcePolicy: req.GrantContext.Policy,
		outputPolicy: req.GrantContext.Policy, sourceDigest: sourceDigest,
		requestDigest: requestDigest, recipientsDigest: recipientsDigest,
	}
	if err := verifyAndConsumeGroupRewrapDecision(d, *req.Decision, execution); err != nil {
		return deny()
	}
	return HandleDEKRewrapForMember(d, req)
}
