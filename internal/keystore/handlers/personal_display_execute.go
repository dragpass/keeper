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
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/secure"
)

// HandlePersonalDisplayExecute verifies and consumes an online decision under
// the request lock, then opens only the current locally proven personal slot.
// The response is sealed to the prepared Extension frame, never plaintext.
func HandlePersonalDisplayExecute(d Deps, payload json.RawMessage) proto.BaseResponse {
	deny := func() proto.BaseResponse {
		return errs.CodeResponse(errs.ErrCodeCryptoFailure, "personal display unavailable")
	}
	if len(payload) > proto.PersonalDisplayExecuteMaxRequestBytes ||
		d.Store == nil || d.ServerKeyVerifier == nil || d.GroupDisplayChallenges == nil {
		return deny()
	}
	var req proto.PersonalDisplayExecuteRequest
	if strictDecodeJSON(payload, &req) != nil || req.Validate() != nil {
		return deny()
	}
	iv, _, ok := decodeBase64(req.Prepare.IVB64, "iv_b64")
	if !ok {
		return deny()
	}
	expiry, _, ok := admitDisplayToken(d, req.Prepare.TokenExpiry, "personal display execute")
	if !ok {
		return deny()
	}
	// Built from the decision's account; the operation digest commits to the
	// prepared AAD and the challenge context to the prepared account.
	aad := []byte(proto.BoundPersonalTokenAAD(req.Decision.AccountID, req.Prepare.DekVersion, expiry))
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
	var op proto.PersonalDisplayOperation
	copy(op.Challenge[:], challenge)
	copy(op.IV[:], iv)
	op.Token = []byte(req.Prepare.Token)
	op.TokenAAD = aad
	op.Ciphertext = ciphertext
	op.FramePublicKeySPKI = frameSPKI
	opDigest := proto.PersonalDisplayOperationDigest(op)
	frameDigest := sha256.Sum256(frameSPKI)
	if req.Decision.OperationDigest != hex.EncodeToString(opDigest[:]) ||
		req.Decision.FrameKeyDigest != hex.EncodeToString(frameDigest[:]) ||
		req.Prepare.TokenID != req.Decision.TokenID ||
		req.Prepare.SessionIssuedAtNanos != strconv.FormatInt(req.Decision.SessionIssuedAtNanos, 10) {
		return deny()
	}
	now := d.Now()
	if req.Decision.IssuedAt > now.Unix()+proto.DisplayDecisionClockSkewSeconds || now.Unix() >= req.Decision.ExpiresAt {
		return deny()
	}
	context, found := d.GroupDisplayChallenges.Peek(req.Decision.Challenge, now)
	if !found || !context.personal || context.accountID != req.Decision.AccountID ||
		context.deviceID != req.Decision.DeviceID || context.tokenID != req.Decision.TokenID ||
		context.sessionStartNanos != req.Decision.SessionIssuedAtNanos ||
		context.operationDigest != opDigest || context.frameKeyDigest != frameDigest ||
		context.personalProvenance.ServerWrapDigest != req.Decision.WrapDigest {
		return deny()
	}
	if err := d.ServerKeyVerifier.Verify(proto.PersonalDisplayDecisionCanonical(req.Decision),
		req.Decision.Signature, req.Decision.ServerKeyVersion); err != nil {
		return deny()
	}
	provenance, err := keychain.ReadPersonalDEKProvenance(d.Store)
	if err != nil || provenance != context.personalProvenance {
		return deny()
	}
	if d.Now().Unix() >= req.Decision.ExpiresAt {
		return deny()
	}
	consumed, found := d.GroupDisplayChallenges.Consume(req.Decision.Challenge, d.Now())
	if !found || consumed != context {
		return deny()
	}
	parsedFrameKey, err := x509.ParsePKIXPublicKey(frameSPKI)
	if err != nil {
		return deny()
	}
	frameECDH, err := parsedFrameKey.(*ecdsa.PublicKey).ECDH()
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
	frameAAD := append([]byte("dragpass.personal.display.frame.v1\x00"), opDigest[:]...)
	sealKey, err := hkdf.Key(sha256.New, shared, challenge, string(frameAAD), 32)
	if err != nil {
		return deny()
	}
	defer secure.Zeroize(sealKey)
	keeperSPKI, err := x509.MarshalPKIXPublicKey(keeperKey.PublicKey())
	if err != nil {
		return deny()
	}
	var sealedIV, sealedCiphertext []byte
	err = keychain.UseVerifiedPersonalSlot(d.Store, context.personalProvenance, func(wrapped, deviceKeyB64 string) error {
		deviceKey, err := base64.StdEncoding.DecodeString(deviceKeyB64)
		if err != nil || len(deviceKey) != 32 {
			return keychain.ErrPersonalDEKProvenance
		}
		defer secure.Zeroize(deviceKey)
		dek, err := unwrapDeviceWrappedDEK(deviceKey, wrapped)
		if err != nil {
			return err
		}
		defer secure.Zeroize(dek)
		if now := d.Now().Unix(); now >= req.Decision.ExpiresAt || expiry.ExpiredAt(now) {
			return keychain.ErrPersonalDEKProvenance
		}
		plaintext, err := crypto.OpenAESGCM(dek, iv, ciphertext, aad)
		if err != nil {
			return err
		}
		defer secure.Zeroize(plaintext)
		sealedIV, sealedCiphertext, err = crypto.SealAESGCM(d.Random(), sealKey, plaintext, frameAAD)
		return err
	})
	if err != nil {
		return deny()
	}
	if now := d.Now().Unix(); now >= req.Decision.ExpiresAt || expiry.ExpiredAt(now) {
		return deny()
	}
	return proto.BaseResponse{Success: true, Data: proto.CurrentGroupDisplayExecuteResponseData{
		Challenge: req.Decision.Challenge, OperationDigest: req.Decision.OperationDigest,
		KeeperPublicKeySPKIB64: base64.StdEncoding.EncodeToString(keeperSPKI),
		IVB64:                  base64.StdEncoding.EncodeToString(sealedIV),
		CiphertextB64:          base64.StdEncoding.EncodeToString(sealedCiphertext),
	}}
}
