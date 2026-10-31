package handlers

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"

	"github.com/awnumar/memguard"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/secure"
)

func HandlePersonalDEKBind(d Deps, req proto.PersonalDEKBindRequest) proto.BaseResponse {
	deny := func() proto.BaseResponse {
		return errs.CodeResponse(errs.ErrCodeCryptoFailure, "personal DEK provenance unavailable")
	}
	if len(req.Password) == 0 || len(req.Password) > 4096 {
		secure.WipeString(&req.Password)
		return deny()
	}
	password := memguard.NewBufferFromBytes([]byte(req.Password))
	secure.WipeString(&req.Password)
	defer password.Destroy()
	proof := req.Proof
	if d.Store == nil || d.ServerKeyVerifier == nil || proof.Validate() != nil || password.Size() == 0 {
		return deny()
	}
	if proof.IssuedAt > d.Now().Unix()+5 || d.Now().Unix() >= proof.ExpiresAt {
		return deny()
	}
	raw, err := base64.StdEncoding.DecodeString(req.EncryptedDEKB64)
	if err != nil || len(raw) != 76 || base64.StdEncoding.EncodeToString(raw) != req.EncryptedDEKB64 {
		return deny()
	}
	digest := sha256.Sum256(raw)
	if hex.EncodeToString(digest[:]) != proof.WrappedDEKDigest {
		return deny()
	}
	if err := d.ServerKeyVerifier.Verify(proto.PersonalDEKBindingCanonical(proof), proof.Signature, proof.ServerKeyVersion); err != nil {
		return deny()
	}
	dek, response := openPasswordWrappedDEK(req.EncryptedDEKB64, password)
	if !response.Success {
		return deny()
	}
	defer secure.Zeroize(dek)
	err = keychain.BindPersonalDEKProvenance(d.Store, keychain.PersonalDEKProvenance{
		AccountID: proof.AccountID, DeviceID: proof.DeviceID, TokenID: proof.TokenID,
		SessionIssuedAtNanos: proof.SessionIssuedAtNanos, LoginGeneration: proof.LoginGeneration, ServerWrapDigest: proof.WrappedDEKDigest,
	}, func(deviceKey, wrapped string) error {
		if d.Now().Unix() >= proof.ExpiresAt {
			return keychain.ErrPersonalDEKProvenance
		}
		key, err := base64.StdEncoding.DecodeString(deviceKey)
		if err != nil {
			return err
		}
		defer secure.Zeroize(key)
		local, err := unwrapDeviceWrappedDEK(key, wrapped)
		if err != nil {
			return err
		}
		defer secure.Zeroize(local)
		if subtle.ConstantTimeCompare(dek, local) != 1 {
			return keychain.ErrPersonalDEKProvenance
		}
		return nil
	})
	if err != nil {
		return deny()
	}
	return proto.BaseResponse{Success: true, Data: struct {
		Bound bool `json:"bound"`
	}{Bound: true}}
}
