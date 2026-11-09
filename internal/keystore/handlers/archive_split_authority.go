package handlers

import (
	"encoding/base64"

	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

func denyArchiveSplit() proto.BaseResponse {
	return errs.CodeResponse(errs.ErrCodeArchiveSplitAuthorityRequired,
		"archive key split requires a server-signed split decision")
}

// HandleArchiveSplitPrepare binds one exact split request to a one-use
// challenge. It records identities and a digest and reads no private key.
func HandleArchiveSplitPrepare(d Deps, r proto.ArchiveSplitPrepareRequest) proto.BaseResponse {
	if r.Validate() != nil || d.Store == nil || d.ArchiveSplitChallenges == nil {
		return denyArchiveSplit()
	}
	binding, found, err := keychain.GetAccountBinding(d.Store)
	if err != nil || !found || binding.SignedOut || binding.Generation == 0 || binding.AccountID != r.Request.AccountID {
		return denyArchiveSplit()
	}
	device, found, err := keychain.GetDeviceID(d.Store)
	if err != nil || !found || device == "" {
		return denyArchiveSplit()
	}
	digest, err := proto.ArchiveSplitRequestDigest(r.Request)
	if err != nil {
		return denyArchiveSplit()
	}
	var random [32]byte
	if err := d.FillRandom(random[:]); err != nil {
		return denyArchiveSplit()
	}
	challenge := base64.RawURLEncoding.EncodeToString(random[:])
	state := archiveShareContext{accountID: binding.AccountID, deviceID: device, tokenID: r.TokenID,
		sessionStartNanos: r.SessionIssuedAtNanos, bindingGeneration: binding.Generation,
		orgID: r.Request.OrgID, operationID: r.Request.OperationID, requestDigest: digest}
	if err := d.ArchiveSplitChallenges.Put(challenge, state, d.Now()); err != nil {
		return denyArchiveSplit()
	}
	return proto.BaseResponse{Success: true, Data: proto.ArchiveSplitPrepareResponseData{Challenge: challenge, RequestDigest: digest}}
}

// HandleArchiveKeySplit is the external split action. The request names its
// own recipient keys, so a paired App process could otherwise collect every
// share under keys it controls. The prepared one-use challenge and the
// server-signed split decision for this exact request are verified, and the
// archive public key compared to the one the decision names, before any
// private-key or journal access. Every refusal here is
// archive_split_authority_required. Dispatch holds requestMu throughout.
func HandleArchiveKeySplit(d Deps, req proto.ArchiveKeySplitRequest) proto.BaseResponse {
	if req.Decision == nil || d.ArchiveSplitChallenges == nil || d.Store == nil || d.ServerKeyVerifier == nil {
		d.Logger.Println("archive key split refused: no signed split decision")
		return denyArchiveSplit()
	}
	decision := *req.Decision
	if decision.Validate() != nil {
		return denyArchiveSplit()
	}
	digest, err := proto.ArchiveSplitRequestDigest(req)
	if err != nil {
		return denyArchiveSplit()
	}
	now := d.Now()
	if decision.IssuedAt > now.Unix()+proto.DisplayDecisionClockSkewSeconds || now.Unix() >= decision.ExpiresAt {
		return denyArchiveSplit()
	}
	entry, found := d.ArchiveSplitChallenges.peekEntry(decision.Challenge, now)
	c := entry.context
	if !found || c.requestDigest != digest || c.requestDigest != decision.RequestDigest ||
		c.accountID != req.AccountID || c.accountID != decision.AccountID ||
		c.orgID != req.OrgID || c.orgID != decision.OrgID ||
		c.operationID != req.OperationID || c.operationID != decision.OperationID ||
		c.deviceID != decision.DeviceID || c.tokenID != decision.TokenID ||
		c.sessionStartNanos != decision.SessionIssuedAtNanos {
		return denyArchiveSplit()
	}
	if !archiveSplitDecisionNamesRequest(decision, req) {
		return denyArchiveSplit()
	}
	if err := d.ServerKeyVerifier.Verify(proto.ArchiveSplitDecisionCanonical(decision), decision.Signature, decision.ServerKeyVersion); err != nil {
		return denyArchiveSplit()
	}
	binding, found, err := keychain.GetAccountBinding(d.Store)
	if err != nil || !found || binding.SignedOut || binding.AccountID != c.accountID || binding.Generation != c.bindingGeneration {
		return denyArchiveSplit()
	}
	device, found, err := keychain.GetDeviceID(d.Store)
	if err != nil || !found || device != c.deviceID {
		return denyArchiveSplit()
	}
	// Public slot only: the key Keeper would split must be the one the server
	// authorized, by both its stored PEM and its parsed SPKI.
	_, activePublic, found, err := keychain.FindArchiveKey(d.Store, keychain.OrgArchiveActiveCandidates(req.OrgID))
	if err != nil || !found || fingerprintBase64Public(activePublic) != decision.ArchiveKeyFingerprint {
		return denyArchiveSplit()
	}
	if spki, err := crypto.RewrapKeyFingerprint(activePublic); err != nil || spki != decision.ArchiveKeySPKIFingerprint {
		return denyArchiveSplit()
	}
	now = d.Now()
	if now.Unix() >= decision.ExpiresAt {
		return denyArchiveSplit()
	}
	consumed, ok := d.ArchiveSplitChallenges.Consume(decision.Challenge, now)
	if !ok || consumed != c {
		return denyArchiveSplit()
	}
	response := prepareArchiveKeySplit(d, req, archiveSplitBinding{
		AccountID: c.accountID, ConfigDigest: decision.ConfigDigest,
		ArchiveKeySPKIFingerprint: decision.ArchiveKeySPKIFingerprint, SplitRequestDigest: digest,
	})
	if !response.Success {
		return response
	}
	if result, ok := response.Data.(proto.ArchiveKeySplitResponseData); !ok || result.KeyFingerprint != decision.ArchiveKeyFingerprint {
		return errs.CodeResponse(errs.ErrCodeNotFound, "archive key changed")
	}
	// The journal already holds the result; a retry under a fresh decision
	// returns it, so late output is withheld rather than released.
	now = d.Now()
	if now.Unix() >= decision.ExpiresAt || !now.Before(entry.expiresAt) {
		return denyArchiveSplit()
	}
	return response
}

// archiveSplitDecisionNamesRequest compares every split parameter the decision
// signs with the request Keeper is about to execute.
func archiveSplitDecisionNamesRequest(decision proto.ArchiveSplitDecision, req proto.ArchiveKeySplitRequest) bool {
	if decision.ConfigDigest != req.ConfigDigest || decision.ThresholdN != req.ThresholdN ||
		len(decision.Recipients) != len(req.RecipientPublicKeys) || len(req.RecipientAccountIDs) != len(req.RecipientPublicKeys) {
		return false
	}
	for i, recipient := range decision.Recipients {
		if recipient.AccountID != req.RecipientAccountIDs[i] ||
			recipient.KeyFingerprint != proto.ArchiveRecipientFingerprint(req.RecipientPublicKeys[i]) {
			return false
		}
	}
	return true
}
