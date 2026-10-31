package handlers

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strconv"

	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/secure"
)

// HandleAuditGroupDisplayExecute seals one authorized audit plaintext to the
// exact prepared frame. The online API wait occurs before dispatch locks it.
func HandleAuditGroupDisplayExecute(d Deps, payload json.RawMessage) proto.BaseResponse {
	deny := func() proto.BaseResponse {
		return errs.CodeResponse(errs.ErrCodeCryptoFailure, "audit display unavailable")
	}
	if len(payload) > proto.AuditGroupDisplayMaxRequestBytes {
		return deny()
	}
	var req proto.AuditGroupDisplayExecuteRequest
	if strictDecodeJSON(payload, &req) != nil || req.Validate() != nil {
		return deny()
	}
	p := req.Prepare
	handle, _, ok := decodeBase64(p.GroupHandle, "group_handle")
	if !ok {
		return deny()
	}
	iv, _, ok := decodeBase64(p.IVB64, "iv_b64")
	if !ok {
		return deny()
	}
	ciphertext, _, ok := decodeBase64(p.CiphertextB64, "ciphertext_b64")
	if !ok {
		return deny()
	}
	frameSPKI, _, ok := decodeBase64(p.FramePublicKeySPKIB64, "frame_public_key_spki_b64")
	if !ok {
		return deny()
	}
	table, _, ok := decodeBase64(p.TableB64, "table_b64")
	if !ok {
		return deny()
	}
	challenge, err := base64.RawURLEncoding.DecodeString(req.Decision.Challenge)
	if err != nil || len(challenge) != 32 {
		return deny()
	}
	var op proto.AuditGroupDisplayOperation
	copy(op.Challenge[:], challenge)
	copy(op.GroupHandle[:], handle)
	copy(op.IV[:], iv)
	op.Token = []byte(p.Token)
	op.Ciphertext = ciphertext
	op.FramePublicKeySPKI = frameSPKI
	op.OrgID = p.OrgID
	op.GroupID = p.GroupID
	op.DekVersion = p.DekVersion
	op.TableID = p.TableID
	op.Table = table
	op.Permit = p.Permit
	opDigest := proto.AuditGroupDisplayOperationDigest(op)
	frameDigest := sha256.Sum256(frameSPKI)
	tableDigest := sha256.Sum256(table)
	if req.Decision.OperationDigest != hex.EncodeToString(opDigest[:]) ||
		req.Decision.FrameKeyDigest != hex.EncodeToString(frameDigest[:]) ||
		req.Decision.TableDigest != hex.EncodeToString(tableDigest[:]) ||
		req.Decision.TableID != p.TableID || req.Decision.GroupID != p.GroupID ||
		req.Decision.DekVersion != p.DekVersion || req.Decision.AccountID != p.Permit.AccountID ||
		req.Decision.TokenID != p.TokenID ||
		p.SessionIssuedAtNanos != strconv.FormatInt(req.Decision.SessionIssuedAtNanos, 10) {
		return deny()
	}
	if verifyAndConsumeAuditGroupDisplayDecision(d, req.Decision, p.GroupHandle) != nil {
		return deny()
	}
	parsedFrameKey, err := x509.ParsePKIXPublicKey(frameSPKI)
	if err != nil {
		return deny()
	}
	frameECDSA, ok := parsedFrameKey.(*ecdsa.PublicKey)
	if !ok {
		return deny()
	}
	frameECDH, err := frameECDSA.ECDH()
	if err != nil {
		return deny()
	}
	keeperKey, err := ecdh.P256().GenerateKey(d.Random())
	if err != nil {
		return deny()
	}
	shared, err := keeperKey.ECDH(frameECDH)
	if err != nil {
		return deny()
	}
	defer secure.Zeroize(shared)
	aad := append([]byte("dragpass.group.display.frame.v1\x00"), opDigest[:]...)
	key, err := hkdf.Key(sha256.New, shared, challenge, string(aad), 32)
	if err != nil {
		return deny()
	}
	defer secure.Zeroize(key)
	keeperSPKI, err := x509.MarshalPKIXPublicKey(keeperKey.PublicKey())
	if err != nil {
		return deny()
	}
	if d.Now().Unix() >= req.Decision.ExpiresAt {
		return deny()
	}
	plaintext, _, ok := openAuditToken(d, p.TokenContext(), p.Permit, p.IVB64, p.CiphertextB64)
	if !ok {
		return deny()
	}
	defer secure.Zeroize(plaintext)
	sealedIV, sealedCiphertext, err := crypto.SealAESGCM(d.Random(), key, plaintext, aad)
	// Sealing may cross the server decision horizon even under requestMu.
	if err != nil || d.Now().Unix() >= req.Decision.ExpiresAt {
		return deny()
	}
	return proto.BaseResponse{Success: true, Data: proto.CurrentGroupDisplayExecuteResponseData{
		Challenge: req.Decision.Challenge, OperationDigest: req.Decision.OperationDigest,
		KeeperPublicKeySPKIB64: base64.StdEncoding.EncodeToString(keeperSPKI),
		IVB64:                  base64.StdEncoding.EncodeToString(sealedIV),
		CiphertextB64:          base64.StdEncoding.EncodeToString(sealedCiphertext),
	}}
}
