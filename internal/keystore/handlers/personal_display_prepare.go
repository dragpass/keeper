package handlers

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strconv"

	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// HandlePersonalDisplayPrepare commits one ciphertext and receiving frame to
// current local personal provenance without opening the DEK or plaintext.
func HandlePersonalDisplayPrepare(d Deps, payload json.RawMessage) proto.BaseResponse {
	deny := func() proto.BaseResponse {
		return errs.CodeResponse(errs.ErrCodeCryptoFailure, "personal display unavailable")
	}
	if len(payload) > proto.PersonalDisplayPrepareMaxRequestBytes || d.Store == nil || d.GroupDisplayChallenges == nil {
		return deny()
	}
	var req proto.PersonalDisplayPrepareRequest
	if strictDecodeJSON(payload, &req) != nil || req.Validate() != nil {
		return deny()
	}
	provenance, err := keychain.ReadPersonalDEKProvenance(d.Store)
	if err != nil {
		return deny()
	}
	expiry, resp, ok := admitDisplayToken(d, req.TokenExpiry, "personal display prepare")
	if !ok {
		return resp
	}
	// The verified provenance names the account whose personal DEK opens the
	// token; a token sealed for another account fails the tag at execute.
	aad := []byte(proto.BoundPersonalTokenAAD(provenance.AccountID, req.DekVersion, expiry))
	iv, _, ok := decodeBase64(req.IVB64, "iv_b64")
	if !ok {
		return deny()
	}
	ciphertext, _, ok := decodeBase64(req.CiphertextB64, "ciphertext_b64")
	if !ok {
		return deny()
	}
	frameSPKI, _, ok := decodeBase64(req.FramePublicKeySPKIB64, "frame_public_key_spki_b64")
	if !ok {
		return deny()
	}
	var challenge [32]byte
	if d.FillRandom(challenge[:]) != nil {
		return deny()
	}
	challengeText := base64.RawURLEncoding.EncodeToString(challenge[:])
	op := proto.PersonalDisplayOperation{Token: []byte(req.Token), TokenAAD: aad, Ciphertext: ciphertext, FramePublicKeySPKI: frameSPKI}
	op.Challenge = challenge
	copy(op.IV[:], iv)
	opDigest := proto.PersonalDisplayOperationDigest(op)
	frameDigest := sha256.Sum256(frameSPKI)
	wrapDigest, err := hex.DecodeString(provenance.ServerWrapDigest)
	if err != nil || len(wrapDigest) != sha256.Size {
		return deny()
	}
	sessionNanos, _ := strconv.ParseInt(req.SessionIssuedAtNanos, 10, 64)
	context := groupDisplayContext{
		personal: true, personalProvenance: provenance,
		accountID: provenance.AccountID, deviceID: provenance.DeviceID,
		tokenID: req.TokenID, sessionStartNanos: sessionNanos,
		bindingGeneration: provenance.BindingGeneration,
		operationDigest:   opDigest, frameKeyDigest: frameDigest,
	}
	if d.GroupDisplayChallenges.Put(challengeText, context, d.Now()) != nil {
		return deny()
	}
	return proto.BaseResponse{Success: true, Data: proto.PersonalDisplayPrepareResponseData{
		Challenge: challengeText, WrapDigest: provenance.ServerWrapDigest,
		OperationDigest: hex.EncodeToString(opDigest[:]), FrameKeyDigest: hex.EncodeToString(frameDigest[:]),
	}}
}
