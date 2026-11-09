package handlers

import (
	"crypto/ed25519"
	"encoding/base64"

	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/secure"
)

func denyArchiveShareProof() proto.BaseResponse {
	return errs.CodeResponse(errs.ErrCodeNotFound, "archive share proof authorization unavailable")
}

// HandleArchiveShareProofPrepare binds one exact proof request to a one-use
// challenge. It records identities and a digest and reads no private key.
func HandleArchiveShareProofPrepare(d Deps, r proto.ArchiveShareProofPrepareRequest) proto.BaseResponse {
	if r.Validate() != nil || d.Store == nil || d.ArchiveProofChallenges == nil {
		return denyArchiveShareProof()
	}
	binding, found, err := keychain.GetAccountBinding(d.Store)
	if err != nil || !found || binding.SignedOut || binding.Generation == 0 || binding.AccountID != r.Request.AccountID {
		return denyArchiveShareProof()
	}
	device, found, err := keychain.GetDeviceID(d.Store)
	if err != nil || !found || device == "" {
		return denyArchiveShareProof()
	}
	digest, err := proto.ArchiveShareOpenProofRequestDigest(r.Request)
	if err != nil {
		return denyArchiveShareProof()
	}
	var random [32]byte
	if err := d.FillRandom(random[:]); err != nil {
		return denyArchiveShareProof()
	}
	challenge := base64.RawURLEncoding.EncodeToString(random[:])
	state := archiveShareContext{accountID: binding.AccountID, deviceID: device, tokenID: r.TokenID,
		sessionStartNanos: r.SessionIssuedAtNanos, bindingGeneration: binding.Generation,
		orgID: r.Request.OrgID, operationID: r.Request.OperationID, shareIndex: r.Request.ShareIndex,
		requestDigest: digest}
	if err := d.ArchiveProofChallenges.Put(challenge, state, d.Now()); err != nil {
		return denyArchiveShareProof()
	}
	return proto.BaseResponse{Success: true, Data: proto.ArchiveShareProofPrepareResponseData{Challenge: challenge, RequestDigest: digest}}
}

// HandleArchiveShareOpenProof verifies the prepared challenge and the signed
// proof decision before reading the account archive key, opens the share,
// checks its embedded index, re-derives the proof key, requires it to equal
// the bound proof public key and signs the proof statement. Only the
// signature leaves Keeper. Dispatch holds requestMu throughout.
func HandleArchiveShareOpenProof(d Deps, req proto.ArchiveShareOpenProofRequest) proto.BaseResponse {
	if req.Decision == nil || d.ArchiveProofChallenges == nil || d.Store == nil || d.ServerKeyVerifier == nil {
		return denyArchiveShareProof()
	}
	decision := *req.Decision
	if decision.Validate() != nil {
		return denyArchiveShareProof()
	}
	digest, err := proto.ArchiveShareOpenProofRequestDigest(req)
	if err != nil {
		return denyArchiveShareProof()
	}
	now := d.Now()
	if decision.IssuedAt > now.Unix()+proto.DisplayDecisionClockSkewSeconds || now.Unix() >= decision.ExpiresAt {
		return denyArchiveShareProof()
	}
	entry, found := d.ArchiveProofChallenges.peekEntry(decision.Challenge, now)
	c := entry.context
	if !found || c.requestDigest != digest || c.requestDigest != decision.RequestDigest ||
		c.accountID != req.AccountID || c.accountID != decision.AccountID ||
		c.orgID != req.OrgID || c.orgID != decision.OrgID ||
		c.operationID != req.OperationID || c.operationID != decision.OperationID ||
		c.shareIndex != req.ShareIndex || c.shareIndex != decision.ShareIndex ||
		c.deviceID != decision.DeviceID || c.tokenID != decision.TokenID ||
		c.sessionStartNanos != decision.SessionIssuedAtNanos ||
		decision.ConfigDigest != req.ConfigDigest || decision.ProofPublicKey != req.ProofPublicKey ||
		decision.ShareDigest != proto.ArchiveShareEnvelopeDigest(req.ShareIndex, req.WrappedKey, req.Ciphertext) {
		return denyArchiveShareProof()
	}
	if err := d.ServerKeyVerifier.Verify(proto.ArchiveShareOpenProofDecisionCanonical(decision), decision.Signature, decision.ServerKeyVersion); err != nil {
		return denyArchiveShareProof()
	}
	binding, found, err := keychain.GetAccountBinding(d.Store)
	if err != nil || !found || binding.SignedOut || binding.AccountID != c.accountID || binding.Generation != c.bindingGeneration {
		return denyArchiveShareProof()
	}
	device, found, err := keychain.GetDeviceID(d.Store)
	if err != nil || !found || device != c.deviceID {
		return denyArchiveShareProof()
	}
	now = d.Now()
	if now.Unix() >= decision.ExpiresAt {
		return denyArchiveShareProof()
	}
	consumed, ok := d.ArchiveProofChallenges.Consume(decision.Challenge, now)
	if !ok || consumed != c {
		return denyArchiveShareProof()
	}
	response := openArchiveShareProof(d, req, decision)
	now = d.Now()
	if now.Unix() >= decision.ExpiresAt || !now.Before(entry.expiresAt) {
		return denyArchiveShareProof()
	}
	return response
}

func openArchiveShareProof(d Deps, req proto.ArchiveShareOpenProofRequest, decision proto.ArchiveShareOpenProofDecision) proto.BaseResponse {
	privKeyBuf, err := GetAccountArchivePrivateKeySecure(d.Store)
	if err != nil {
		return errs.Response(err) // not_found if this account has no archive key
	}
	defer privKeyBuf.Destroy()
	priv, err := crypto.ParsePrivateKey(string(privKeyBuf.Bytes()))
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeCryptoFailure, "parse account archive private key failed")
	}
	opened, err := crypto.HybridUnwrap(priv, req.WrappedKey, req.Ciphertext)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeCryptoFailure, "share unwrap failed")
	}
	defer secure.Zeroize(opened)
	share, err := crypto.DeserializeShare(opened)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeCryptoFailure, "share is malformed")
	}
	secure.Zeroize(share.Y)
	if int(share.X) != req.ShareIndex {
		return errs.CodeResponse(errs.ErrCodeCryptoFailure, "share index does not match the share")
	}
	proofKey, err := deriveArchiveShareProofKey(opened, req.OperationID, req.ShareIndex)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeCryptoFailure, "derive share proof key failed")
	}
	defer secure.Zeroize(proofKey)
	if base64.StdEncoding.EncodeToString(proofKey.Public().(ed25519.PublicKey)) != decision.ProofPublicKey {
		return errs.CodeResponse(errs.ErrCodeCryptoFailure, "share does not derive the bound proof key")
	}
	signature := ed25519.Sign(proofKey, []byte(proto.ArchiveShareOpenProofStatement(decision)))
	d.Logger.Println("archive share open proof signed (share never left Keeper)")
	return proto.BaseResponse{Success: true, Data: proto.ArchiveShareOpenProofResponseData{
		Signature: base64.StdEncoding.EncodeToString(signature),
	}}
}
