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
	"github.com/dragpass/keeper/internal/keystore/sessions"
)

// HandleGroupDisplayExecute consumes one current server decision and seals
// plaintext to the prepared Extension frame. Dispatch holds requestMu across
// verification and the protected operation; this handler never waits online.
func HandleGroupDisplayExecute(d Deps, payload json.RawMessage) proto.BaseResponse {
	deny := func() proto.BaseResponse {
		return errs.CodeResponse(errs.ErrCodeCryptoFailure, "group display unavailable")
	}
	if len(payload) > proto.CurrentGroupDisplayExecuteMaxRequestBytes {
		return deny()
	}
	var req proto.CurrentGroupDisplayExecuteRequest
	if err := strictDecodeJSON(payload, &req); err != nil {
		return deny()
	}
	if err := req.Validate(); err != nil {
		return deny()
	}
	handle, _, ok := decodeBase64(req.Prepare.GroupHandle, "group_handle")
	if !ok {
		return deny()
	}
	iv, _, ok := decodeBase64(req.Prepare.IVB64, "iv_b64")
	if !ok {
		return deny()
	}
	ciphertext, _, ok := decodeBase64(req.Prepare.CiphertextB64, "ciphertext_b64")
	if !ok {
		return deny()
	}
	frameSPKI, _, ok := decodeBase64(req.Prepare.FramePublicKeySPKIB64, "frame_public_key_spki_b64")
	if !ok {
		return deny()
	}
	challenge, err := base64.RawURLEncoding.DecodeString(req.Decision.Challenge)
	if err != nil || len(challenge) != 32 {
		return deny()
	}
	var op proto.CurrentGroupDisplayOperation
	copy(op.Challenge[:], challenge)
	copy(op.GroupHandle[:], handle)
	copy(op.IV[:], iv)
	op.Token = []byte(req.Prepare.Token)
	op.Ciphertext = ciphertext
	op.FramePublicKeySPKI = frameSPKI
	opDigest := proto.CurrentGroupDisplayOperationDigest(op)
	frameDigest := sha256.Sum256(frameSPKI)
	if req.Decision.OperationDigest != hex.EncodeToString(opDigest[:]) ||
		req.Decision.FrameKeyDigest != hex.EncodeToString(frameDigest[:]) ||
		req.Prepare.TokenID != req.Decision.TokenID ||
		req.Prepare.SessionIssuedAtNanos != strconv.FormatInt(req.Decision.SessionIssuedAtNanos, 10) {
		return deny()
	}
	if err := verifyAndConsumeCurrentGroupDisplayDecision(d, req.Decision, req.Prepare.GroupHandle); err != nil {
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
	var sealedIV, sealedCiphertext []byte
	useErr := d.GroupSessions.UseLabeled(req.Prepare.GroupHandle, func(groupDEK []byte, label sessions.Label) error {
		if isAuditOnlyLabel(label) {
			return errHandleAuditOnly
		}
		plaintext, err := crypto.OpenAESGCM(groupDEK, iv, ciphertext, nil)
		if err != nil {
			return err
		}
		defer secure.Zeroize(plaintext)
		sealedIV, sealedCiphertext, err = crypto.SealAESGCM(d.Random(), key, plaintext, aad)
		return err
	})
	if useErr != nil {
		return deny()
	}
	return proto.BaseResponse{Success: true, Data: proto.CurrentGroupDisplayExecuteResponseData{
		Challenge:              req.Decision.Challenge,
		OperationDigest:        req.Decision.OperationDigest,
		KeeperPublicKeySPKIB64: base64.StdEncoding.EncodeToString(keeperSPKI),
		IVB64:                  base64.StdEncoding.EncodeToString(sealedIV),
		CiphertextB64:          base64.StdEncoding.EncodeToString(sealedCiphertext),
	}}
}
