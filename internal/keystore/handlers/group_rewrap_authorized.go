package handlers

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"

	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

var errInvalidBatchRewrap = errors.New("invalid batch rewrap commitment")

func batchRewrapCommitments(req proto.DEKUnwrapAndRewrapForManyRequest) (groupRewrapContext, string, []proto.RewrapRecipientCommitment, error) {
	if req.Validate() != nil || req.GrantContext == nil || req.OwnerAccountID == "" {
		return groupRewrapContext{}, "", nil, errInvalidBatchRewrap
	}
	source, err := base64.StdEncoding.DecodeString(req.WrappedForMeB64)
	if err != nil {
		return groupRewrapContext{}, "", nil, errInvalidBatchRewrap
	}
	recipients := make([]proto.RewrapRecipientCommitment, 0, len(req.Recipients))
	for _, recipient := range req.Recipients {
		fingerprint, err := crypto.RewrapKeyFingerprint(recipient.PublicKey)
		if err != nil {
			return groupRewrapContext{}, "", nil, errInvalidBatchRewrap
		}
		kind := "self"
		if recipient.OrgArchive {
			kind = "archive"
		} else if recipient.AccountID != "" {
			kind = "account"
		}
		recipients = append(recipients, proto.RewrapRecipientCommitment{
			Kind: kind, AccountID: recipient.AccountID, KeyFingerprint: fingerprint,
		})
	}
	recipientsText, err := proto.RewrapRecipientsDigest(recipients)
	if err != nil {
		return groupRewrapContext{}, "", nil, errInvalidBatchRewrap
	}
	recipientsBytes, err := hex.DecodeString(recipientsText)
	if err != nil {
		return groupRewrapContext{}, "", nil, errInvalidBatchRewrap
	}
	requestDigest, err := proto.GroupRewrapManyRequestDigest(req)
	if err != nil {
		return groupRewrapContext{}, "", nil, errInvalidBatchRewrap
	}
	context := groupRewrapContext{
		orgID: req.GrantContext.OrgID, groupID: req.GrantContext.GroupID,
		dekVersion: req.GrantContext.DekVersion, sourcePolicy: req.GrantContext.Policy,
		outputPolicy: req.OutputGrantContext().Policy, sourceDigest: sha256.Sum256(source),
		requestDigest: requestDigest,
	}
	copy(context.recipientsDigest[:], recipientsBytes)
	return context, recipientsText, recipients, nil
}

// The App can name a generated source, but only Keeper's live generation
// handle proves that this exact ciphertext was created here for this account.
func generatedRewrapSourceMatches(d Deps, req proto.DEKUnwrapAndRewrapForManyRequest, digest [sha256.Size]byte) bool {
	if d.GroupSessions == nil || d.Store == nil || req.SourceHandle == "" || req.GrantContext == nil {
		return false
	}
	label, err := d.GroupSessions.LabelFor(req.SourceHandle)
	if err != nil || label.GeneratedSourceDigest == ([sha256.Size]byte{}) ||
		label.GeneratedSourceDigest != digest || label.OrgID != req.GrantContext.OrgID ||
		label.GroupID != req.GrantContext.GroupID || label.DekVersion != req.GrantContext.DekVersion ||
		label.GrantPolicy != req.GrantContext.Policy || label.GeneratedAccountID != req.OwnerAccountID {
		return false
	}
	binding, found, err := keychain.GetAccountBinding(d.Store)
	return err == nil && found && !binding.SignedOut && binding.Generation != 0 &&
		binding.AccountID == label.GeneratedAccountID && binding.Generation == label.GeneratedBindingGeneration
}

// HandleAuthorizedDEKRewrapForMember is the external execution boundary. The
// dispatcher holds requestMu through this check and the subsequent wrap.
func HandleAuthorizedDEKRewrapForMember(d Deps, req proto.DEKRewrapForMemberRequest) proto.BaseResponse {
	deny := func() proto.BaseResponse {
		return errs.CodeResponse(errs.ErrCodeNotFound, "Group rewrap unavailable")
	}
	if req.Validate() != nil || req.Decision == nil || req.GrantContext == nil ||
		req.OwnerAccountID == "" || req.OtherAccountID == "" ||
		!proto.ValidMemberRewrapContext(req.Operation, req.SourceKind) {
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
	deadline, err := verifyAndConsumeGroupRewrapDecision(d, *req.Decision, execution)
	if err != nil {
		return deny()
	}
	response := HandleDEKRewrapForMember(d, req)
	// Key access and wrapping can outlast the authorization horizon.
	now := d.Now()
	if response.Success && (now.Unix() >= req.Decision.ExpiresAt || !now.Before(deadline)) {
		return deny()
	}
	return response
}

// HandleAuthorizedDEKUnwrapAndRewrapForMany is the external batch boundary.
// It refuses every batch until a prepared, server-authorized decision binds
// all recipients before the first peer pin can be changed.
func HandleAuthorizedDEKUnwrapAndRewrapForMany(d Deps, req proto.DEKUnwrapAndRewrapForManyRequest) proto.BaseResponse {
	deny := func() proto.BaseResponse {
		return errs.CodeResponse(errs.ErrCodeNotFound, "Group rewrap unavailable")
	}
	if req.Decision == nil ||
		((req.Operation != "rotation_old_grants" || req.SourceKind != "stored_member") &&
			(req.Operation != "audit_relabel" || req.SourceKind != "retained_member") &&
			(req.Operation != "rotation_new_dek" || req.SourceKind != "keeper_generated")) {
		return deny()
	}
	if (req.SourceKind == "keeper_generated") != (req.SourceHandle != "") {
		return deny()
	}
	execution, _, _, err := batchRewrapCommitments(req)
	if err != nil {
		return deny()
	}
	if req.SourceKind == "keeper_generated" && !generatedRewrapSourceMatches(d, req, execution.sourceDigest) {
		return deny()
	}
	execution.operation = req.Operation
	execution.sourceKind = req.SourceKind
	deadline, err := verifyAndConsumeGroupRewrapDecision(d, *req.Decision, execution)
	if err != nil {
		return deny()
	}
	response := HandleDEKUnwrapAndRewrapForMany(d, req)
	// Key access and wrapping can outlast the authorization horizon.
	now := d.Now()
	if response.Success && (now.Unix() >= req.Decision.ExpiresAt || !now.Before(deadline)) {
		return deny()
	}
	return response
}
