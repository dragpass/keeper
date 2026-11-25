package handlers

import (
	"encoding/base64"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// Preparation records identities and a digest, never a private key or share.
func HandleArchiveSharePrepare(d Deps, r proto.ArchiveSharePrepareRequest) proto.BaseResponse {
	deny := func() proto.BaseResponse {
		return errs.CodeResponse(errs.ErrCodeNotFound, "archive share authorization unavailable")
	}
	if r.Request.Decision != nil || r.Validate() != nil || d.Store == nil || d.ArchiveShareChallenges == nil {
		return deny()
	}
	binding, found, err := keychain.GetAccountBinding(d.Store)
	if err != nil || !found || binding.SignedOut || binding.Generation == 0 || binding.AccountID != r.Request.AccountID {
		return deny()
	}
	device, found, err := keychain.GetDeviceID(d.Store)
	if err != nil || !found || device == "" {
		return deny()
	}
	digest, err := proto.ArchiveShareRequestDigest(r.Request)
	if err != nil {
		return deny()
	}
	var random [32]byte
	if err := d.FillRandom(random[:]); err != nil {
		return deny()
	}
	challenge := base64.RawURLEncoding.EncodeToString(random[:])
	state := archiveShareContext{accountID: binding.AccountID, deviceID: device, tokenID: r.TokenID, sessionStartNanos: r.SessionIssuedAtNanos, bindingGeneration: binding.Generation, orgID: r.Request.OrgID, recoverySessionID: r.Request.RecoverySessionID, requestDigest: digest}
	state.operationID = r.Request.SplitOperationID
	prepared := proto.ArchiveSharePrepareResponseData{Challenge: challenge, RequestDigest: digest}
	if t := r.Request.RecoveryTarget; t != nil {
		state.recoveryTarget = *t
	} else {
		source := r.Request.SourceTarget
		state.sourceRequester, state.sourceConfig, state.sourceRound = source.RequesterAccountID, source.ConfigDigest, *source.SessionRound
	}
	trust, err := usableTrust(d)
	if err != nil || trust == nil || trust.ConfigDigest == "" {
		return deny()
	}
	anchor, _, err := keychain.GetKeyTransparencyCheckpoint(d.Store)
	if err != nil {
		return deny()
	}
	prepared.PreviousTreeSize = &anchor.Size
	owner, found, err := keychain.GetPeerKeyOwner(d.Store)
	if err != nil || (found && owner.AccountID != binding.AccountID) {
		return deny()
	}
	if found {
		pin, err := loadPeerKeyPin(d.Store, owner.AccountID, r.Request.RequesterAccount())
		if err != nil {
			return deny()
		}
		if enrollmentRooted(d, pin, owner.AccountID, r.Request.RequesterAccount()) {
			prepared.RequesterPinFingerprint = pin.Fingerprint
		}
	}
	if err := d.ArchiveShareChallenges.Put(challenge, state, d.Now()); err != nil {
		return deny()
	}
	return proto.BaseResponse{Success: true, Data: prepared}
}

// Dispatch holds requestMu through verification and cryptography. The online
// request happens between preparation and execution, outside that lock.
func HandleArchiveShareRewrap(d Deps, req proto.ArchiveShareRewrapRequest) proto.BaseResponse {
	deny := func() proto.BaseResponse {
		return errs.CodeResponse(errs.ErrCodeNotFound, "archive share authorization unavailable")
	}
	if req.Decision == nil || d.ArchiveShareChallenges == nil || d.Store == nil || d.ServerKeyVerifier == nil {
		return deny()
	}
	decision := *req.Decision
	if decision.Validate() != nil {
		return deny()
	}
	digest, err := proto.ArchiveShareRequestDigest(req)
	if err != nil {
		return deny()
	}
	now := d.Now()
	if decision.IssuedAt > now.Unix()+proto.DisplayDecisionClockSkewSeconds || now.Unix() >= decision.ExpiresAt {
		return deny()
	}
	entry, found := d.ArchiveShareChallenges.peekEntry(decision.Challenge, now)
	c := entry.context
	if c.operationID != req.SplitOperationID || c.operationID != decision.SplitOperationID {
		return deny()
	}
	if t := req.SourceTarget; t != nil && (t.RequesterAccountID != c.sourceRequester || t.ConfigDigest != c.sourceConfig || *t.SessionRound != c.sourceRound) {
		return deny()
	}
	if t := req.RecoveryTarget; t != nil && *t != c.recoveryTarget {
		return deny()
	}
	if !found || c.requestDigest != digest || c.requestDigest != decision.RequestDigest || c.accountID != req.AccountID || c.accountID != decision.AccountID || c.orgID != req.OrgID || c.orgID != decision.OrgID || c.recoverySessionID != req.RecoverySessionID || c.recoverySessionID != decision.RecoverySessionID || c.deviceID != decision.DeviceID || c.tokenID != decision.TokenID || c.sessionStartNanos != decision.SessionIssuedAtNanos {
		return deny()
	}
	if err := d.ServerKeyVerifier.Verify(proto.ArchiveShareDecisionCanonical(decision), decision.Signature, decision.ServerKeyVersion); err != nil {
		return deny()
	}
	binding, found, err := keychain.GetAccountBinding(d.Store)
	if err != nil || !found || binding.SignedOut || binding.AccountID != c.accountID || binding.Generation != c.bindingGeneration {
		return deny()
	}
	device, found, err := keychain.GetDeviceID(d.Store)
	if err != nil || !found || device != c.deviceID {
		return deny()
	}
	now = d.Now()
	if now.Unix() >= decision.ExpiresAt {
		return deny()
	}
	consumed, ok := d.ArchiveShareChallenges.Consume(decision.Challenge, now)
	if !ok || consumed != c {
		return deny()
	}
	response := rewrapArchiveShare(d, req)
	now = d.Now()
	if now.Unix() >= decision.ExpiresAt || !now.Before(entry.expiresAt) {
		return deny()
	}
	return response
}
