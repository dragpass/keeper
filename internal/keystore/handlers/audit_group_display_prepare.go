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

// HandleAuditGroupDisplayPrepare binds an audit token and permit to one frame.
// It does not consume the permit or open the handle.
func HandleAuditGroupDisplayPrepare(d Deps, payload json.RawMessage) proto.BaseResponse {
	deny := func() proto.BaseResponse {
		return errs.CodeResponse(errs.ErrCodeCryptoFailure, "audit display unavailable")
	}
	if len(payload) > proto.AuditGroupDisplayMaxRequestBytes {
		return deny()
	}
	var req proto.AuditGroupDisplayPrepareRequest
	if strictDecodeJSON(payload, &req) != nil || req.Validate() != nil {
		return deny()
	}
	if d.Store == nil || d.GroupSessions == nil || d.GroupDisplayChallenges == nil {
		return deny()
	}
	// Audit-only tokens carry no authenticated expiry; refuse before the
	// table preflight so an unverifiable token spends nothing.
	if !admitAuditDisplayToken(d) {
		return displayTokenRefused()
	}
	table, _, ok := auditPreflight(d, req.TokenContext())
	if !ok {
		return deny()
	}
	label, err := d.GroupSessions.LabelOf(req.GroupHandle)
	if err != nil || label.GrantDigest == [32]byte{} {
		return deny()
	}
	binding, found, err := keychain.GetAccountBinding(d.Store)
	if err != nil || !found || binding.SignedOut || binding.AccountID == "" || binding.Generation == 0 || binding.AccountID != req.Permit.AccountID {
		return deny()
	}
	deviceID, found, err := keychain.GetDeviceID(d.Store)
	if err != nil || !found || deviceID == "" {
		return deny()
	}
	handle, _, ok := decodeBase64(req.GroupHandle, "group_handle")
	if !ok {
		return deny()
	}
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
	op := proto.AuditGroupDisplayOperation{
		CurrentGroupDisplayOperation: proto.CurrentGroupDisplayOperation{Challenge: challenge, Token: []byte(req.Token), Ciphertext: ciphertext, FramePublicKeySPKI: frameSPKI},
		OrgID:                        req.OrgID, GroupID: req.GroupID, DekVersion: req.DekVersion,
		TableID: req.TableID, Table: table, Permit: req.Permit,
	}
	copy(op.GroupHandle[:], handle)
	copy(op.IV[:], iv)
	opDigest := proto.AuditGroupDisplayOperationDigest(op)
	frameDigest := sha256.Sum256(frameSPKI)
	tableDigest := sha256.Sum256(table)
	sessionNanos, _ := strconv.ParseInt(req.SessionIssuedAtNanos, 10, 64)
	context := groupDisplayContext{
		audit: true, auditTableID: req.TableID, auditTableDigest: tableDigest,
		groupHandle: req.GroupHandle, accountID: binding.AccountID, deviceID: deviceID,
		tokenID: req.TokenID, sessionStartNanos: sessionNanos, bindingGeneration: binding.Generation,
		operationDigest: opDigest, frameKeyDigest: frameDigest,
	}
	if d.GroupDisplayChallenges.Put(challengeText, context, d.Now()) != nil {
		return deny()
	}
	return proto.BaseResponse{Success: true, Data: proto.AuditGroupDisplayPrepareResponseData{
		Challenge: challengeText, GroupID: label.GroupID, DekVersion: label.DekVersion,
		GrantDigest: hex.EncodeToString(label.GrantDigest[:]), TableID: req.TableID,
		TableDigest: hex.EncodeToString(tableDigest[:]), OperationDigest: hex.EncodeToString(opDigest[:]),
		FrameKeyDigest: hex.EncodeToString(frameDigest[:]),
	}}
}
