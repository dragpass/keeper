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

// HandleGroupDisplayPrepare binds one ciphertext-only display attempt to the
// current local account and device. It never opens a Group DEK or plaintext.
func HandleGroupDisplayPrepare(d Deps, payload json.RawMessage) proto.BaseResponse {
	if len(payload) > proto.CurrentGroupDisplayPrepareMaxRequestBytes {
		return errs.CodeResponse(errs.ErrCodeValidation, "invalid group display request")
	}
	var req proto.CurrentGroupDisplayPrepareRequest
	if err := strictDecodeJSON(payload, &req); err != nil {
		return errs.CodeResponse(errs.ErrCodeValidation, "invalid group display request")
	}
	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}
	if d.Store == nil || d.GroupSessions == nil || d.GroupDisplayChallenges == nil {
		return errs.CodeResponse(errs.ErrCodeNotFound, "group display unavailable")
	}
	label, err := d.GroupSessions.LabelOf(req.GroupHandle)
	if err != nil || label.OrgID == "" || label.GroupID == "" || label.DekVersion <= 0 ||
		label.GrantDigest == [sha256.Size]byte{} ||
		(label.GrantPolicy != proto.GrantPolicyLegacy && label.GrantPolicy != proto.GrantPolicyDecryptOnlyV1) {
		return errs.CodeResponse(errs.ErrCodeNotFound, "group display unavailable")
	}
	binding, found, err := keychain.GetAccountBinding(d.Store)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "account binding unavailable")
	}
	if !found || binding.SignedOut || binding.AccountID == "" || binding.Generation == 0 {
		return errs.CodeResponse(errs.ErrCodeNotFound, "group display unavailable")
	}
	deviceID, found, err := keychain.GetDeviceID(d.Store)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "device binding unavailable")
	}
	if !found || deviceID == "" {
		return errs.CodeResponse(errs.ErrCodeNotFound, "group display unavailable")
	}

	handle, resp, ok := decodeBase64(req.GroupHandle, "group_handle")
	if !ok {
		return resp
	}
	iv, resp, ok := decodeBase64(req.IVB64, "iv_b64")
	if !ok {
		return resp
	}
	ciphertext, resp, ok := decodeBase64(req.CiphertextB64, "ciphertext_b64")
	if !ok {
		return resp
	}
	frameSPKI, resp, ok := decodeBase64(req.FramePublicKeySPKIB64, "frame_public_key_spki_b64")
	if !ok {
		return resp
	}
	var challenge [32]byte
	if err := d.FillRandom(challenge[:]); err != nil {
		return errs.CodeResponse(errs.ErrCodeInternal, "group display preparation unavailable")
	}
	challengeText := base64.RawURLEncoding.EncodeToString(challenge[:])
	op := proto.CurrentGroupDisplayOperation{Token: []byte(req.Token), Ciphertext: ciphertext, FramePublicKeySPKI: frameSPKI}
	op.Challenge = challenge
	copy(op.GroupHandle[:], handle)
	copy(op.IV[:], iv)
	operationDigest := proto.CurrentGroupDisplayOperationDigest(op)
	frameDigest := sha256.Sum256(frameSPKI)
	sessionStartNanos, _ := strconv.ParseInt(req.SessionIssuedAtNanos, 10, 64) // Validate checked the canonical int64.
	context := groupDisplayContext{
		groupHandle: req.GroupHandle, accountID: binding.AccountID, deviceID: deviceID,
		tokenID: req.TokenID, sessionStartNanos: sessionStartNanos,
		bindingGeneration: binding.Generation, operationDigest: operationDigest,
		frameKeyDigest: frameDigest,
	}
	if err := d.GroupDisplayChallenges.Put(challengeText, context, d.Now()); err != nil {
		return errs.CodeResponse(errs.ErrCodeInternal, "group display preparation unavailable")
	}
	return proto.BaseResponse{Success: true, Data: proto.CurrentGroupDisplayPrepareResponseData{
		Challenge: challengeText, GroupID: label.GroupID, DekVersion: label.DekVersion,
		GrantDigest:     hex.EncodeToString(label.GrantDigest[:]),
		OperationDigest: hex.EncodeToString(operationDigest[:]),
		FrameKeyDigest:  hex.EncodeToString(frameDigest[:]),
	}}
}
