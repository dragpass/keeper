package handlers

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"

	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// HandleGroupRewrapPrepare records an exact local request without reading a
// private key, consulting a peer pin, or creating any wrapped output.
func HandleGroupRewrapPrepare(d Deps, req proto.GroupRewrapPrepareRequest) proto.BaseResponse {
	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}
	if d.Store == nil || d.GroupRewrapChallenges == nil {
		return errs.CodeResponse(errs.ErrCodeNotFound, "Group rewrap unavailable")
	}
	binding, found, err := keychain.GetAccountBinding(d.Store)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "account binding unavailable")
	}
	ownerAccountID := req.Member.OwnerAccountID
	if req.Many != nil {
		ownerAccountID = req.Many.OwnerAccountID
	}
	if req.Combine != nil {
		ownerAccountID = req.Combine.OwnerAccountID
	}
	if req.Archive != nil {
		ownerAccountID = req.Archive.OwnerAccountID
	}
	if !found || binding.SignedOut || binding.Generation == 0 || binding.AccountID != ownerAccountID {
		return errs.CodeResponse(errs.ErrCodeNotFound, "Group rewrap unavailable")
	}
	deviceID, found, err := keychain.GetDeviceID(d.Store)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "device binding unavailable")
	}
	if !found || deviceID == "" {
		return errs.CodeResponse(errs.ErrCodeNotFound, "Group rewrap unavailable")
	}
	if req.Many != nil || req.Combine != nil || req.Archive != nil {
		var context groupRewrapContext
		var recipientsDigestText string
		var recipients []proto.RewrapRecipientCommitment
		var err error
		if req.Archive != nil {
			if !archiveRotationStageMatches(d, *req.Archive) {
				return errs.CodeResponse(errs.ErrCodeNotFound, "Group rewrap unavailable")
			}
			context, recipientsDigestText, recipients, err = archiveRewrapCommitments(*req.Archive)
		} else if req.Combine != nil {
			context, recipientsDigestText, recipients, err = combineRewrapCommitments(*req.Combine)
		} else {
			context, recipientsDigestText, recipients, err = batchRewrapCommitments(*req.Many)
		}
		if err != nil {
			return errs.CodeResponse(errs.ErrCodeValidation, "invalid batch rewrap request")
		}
		if req.SourceKind == "keeper_generated" && !generatedRewrapSourceMatches(d, *req.Many, context.sourceDigest) {
			return errs.CodeResponse(errs.ErrCodeNotFound, "Group rewrap unavailable")
		}
		context.accountID = binding.AccountID
		context.deviceID = deviceID
		context.tokenID = req.TokenID
		context.sessionStartNanos = req.SessionIssuedAtNanos
		context.bindingGeneration = binding.Generation
		context.operation = req.Operation
		context.sourceKind = req.SourceKind
		var challenge [32]byte
		if err := d.FillRandom(challenge[:]); err != nil {
			return errs.CodeResponse(errs.ErrCodeInternal, "Group rewrap unavailable")
		}
		challengeText := base64.RawURLEncoding.EncodeToString(challenge[:])
		if err := d.GroupRewrapChallenges.Put(challengeText, context, d.Now()); err != nil {
			return errs.CodeResponse(errs.ErrCodeInternal, "Group rewrap unavailable")
		}
		recipientAccountID, recipientFingerprint := "", ""
		if req.Archive != nil {
			recipientAccountID, recipientFingerprint = recipients[0].AccountID, recipients[0].KeyFingerprint
		}
		return proto.BaseResponse{Success: true, Data: proto.GroupRewrapPrepareResponseData{
			RecipientAccountID: recipientAccountID, RecipientKeyFingerprint: recipientFingerprint,
			Challenge: challengeText, Operation: req.Operation, OrgID: context.orgID,
			GroupID: context.groupID, DEKVersion: context.dekVersion, SourceKind: context.sourceKind,
			SourceGrantDigest: hex.EncodeToString(context.sourceDigest[:]),
			SourcePolicy:      context.sourcePolicy, OutputPolicy: context.outputPolicy,
			RequestDigest:    hex.EncodeToString(context.requestDigest[:]),
			RecipientsDigest: recipientsDigestText, Recipients: recipients,
		}}
	}
	source, err := base64.StdEncoding.DecodeString(req.Member.WrappedForMeB64)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeValidation, "invalid source grant")
	}
	sourceDigest := sha256.Sum256(source)
	fingerprint, err := crypto.RewrapKeyFingerprint(req.Member.OtherPublicKey)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeValidation, "invalid recipient key")
	}
	recipientsDigestText, err := proto.RewrapRecipientsDigest([]proto.RewrapRecipientCommitment{{
		Kind: "account", AccountID: req.Member.OtherAccountID, KeyFingerprint: fingerprint,
	}})
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeValidation, "invalid recipient")
	}
	var recipientsDigest [sha256.Size]byte
	decoded, _ := hex.DecodeString(recipientsDigestText)
	copy(recipientsDigest[:], decoded)
	requestDigest, err := proto.GroupRewrapMemberRequestDigest(req.Member)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeValidation, "invalid rewrap request")
	}
	var challenge [32]byte
	if err := d.FillRandom(challenge[:]); err != nil {
		return errs.CodeResponse(errs.ErrCodeInternal, "Group rewrap unavailable")
	}
	challengeText := base64.RawURLEncoding.EncodeToString(challenge[:])
	context := groupRewrapContext{
		accountID: binding.AccountID, deviceID: deviceID, tokenID: req.TokenID,
		sessionStartNanos: req.SessionIssuedAtNanos, bindingGeneration: binding.Generation,
		operation: req.Operation, orgID: req.Member.GrantContext.OrgID,
		groupID: req.Member.GrantContext.GroupID, dekVersion: req.Member.GrantContext.DekVersion,
		sourceKind: req.SourceKind, sourcePolicy: req.Member.GrantContext.Policy,
		outputPolicy: req.Member.GrantContext.Policy, sourceDigest: sourceDigest,
		requestDigest: requestDigest, recipientsDigest: recipientsDigest,
	}
	if err := d.GroupRewrapChallenges.Put(challengeText, context, d.Now()); err != nil {
		return errs.CodeResponse(errs.ErrCodeInternal, "Group rewrap unavailable")
	}
	return proto.BaseResponse{Success: true, Data: proto.GroupRewrapPrepareResponseData{
		Challenge: challengeText, Operation: req.Operation, OrgID: context.orgID,
		GroupID: context.groupID, DEKVersion: context.dekVersion, SourceKind: context.sourceKind,
		SourceGrantDigest: hex.EncodeToString(sourceDigest[:]),
		SourcePolicy:      context.sourcePolicy, OutputPolicy: context.outputPolicy,
		RequestDigest:    hex.EncodeToString(requestDigest[:]),
		RecipientsDigest: recipientsDigestText, RecipientAccountID: req.Member.OtherAccountID,
		RecipientKeyFingerprint: fingerprint,
	}}
}
