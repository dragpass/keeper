// rotate_keypair.go — voluntary user RSA keypair rotation (Prepare + Promote).
//
// Stuck-state diagnostic/cleanup (Status / Abort) lives in
// rotate_keypair_status.go.

package handlers

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/awnumar/memguard"

	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/secure"
)

const rotateKeyConfirmationPayloadType = "rotate_key_confirmation:v1"

type rotateKeyConfirmationPayload struct {
	Type                   string `json:"type"`
	ConfirmationToken      string `json:"confirmation_token"`
	AccountID              string `json:"account_id"`
	PendingPublicKeySHA256 string `json:"pending_public_key_sha256"`
	ExpiresAt              int64  `json:"expires_at"`
}

// HandleRotateUserKeypairPrepare — generates a new keypair + signs with both.
func HandleRotateUserKeypairPrepare(d Deps, req proto.RotateUserKeypairPrepareRequest) proto.BaseResponse {
	d.Logger.Println("rotate user keypair prepare request processing...")

	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}

	// Wraps the 4-step server signature verification into a single helper call.
	if ok, resp := verifyServerSig(d, req.ChallengeToken, req.ServerSignature, req.ServerKeyVersion, "rotate keypair prepare"); !ok {
		return resp
	}

	// Overwrites any existing pending — UX is "restart" with a fresh keypair.
	// (A previous prepare may have ended without promote; if the caller wanted
	// to retry, an explicit cancel would be expected, but the first iteration
	// just overwrites.)
	_ = keychain.DeletePendingPrivateKey(d.Store)
	_ = keychain.DeletePendingPublicKey(d.Store)

	// generate new keypair
	keyPair, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeInternal, "keypair generation failed: "+err.Error())
	}

	// save into pending slot (briefly protected with memguard)
	pendingPrivBuf := memguard.NewBufferFromBytes([]byte(keyPair.PrivateKey))
	secure.WipeString(&keyPair.PrivateKey)
	defer pendingPrivBuf.Destroy()

	if err := keychain.SavePendingPrivateKey(d.Store, string(pendingPrivBuf.Bytes())); err != nil {
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "save pending private key: "+err.Error())
	}
	if err := keychain.SavePendingPublicKey(d.Store, keyPair.PublicKey); err != nil {
		_ = keychain.DeletePendingPrivateKey(d.Store)
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "save pending public key: "+err.Error())
	}

	// sign the challenge with ACTIVE (OLD) private key (proves OLD ownership)
	oldPrivBuf, err := getPrivateKeySecure(d.Store)
	if err != nil {
		_ = keychain.DeletePendingPrivateKey(d.Store)
		_ = keychain.DeletePendingPublicKey(d.Store)
		return errs.CodeResponse(errs.ErrCodeNotFound, "active keypair not found (signup required first): "+err.Error())
	}
	defer oldPrivBuf.Destroy()
	oldSigB64, err := signDataSecure(oldPrivBuf, req.ChallengeToken)
	if err != nil {
		_ = keychain.DeletePendingPrivateKey(d.Store)
		_ = keychain.DeletePendingPublicKey(d.Store)
		return errs.CodeResponse(errs.ErrCodeCryptoFailure, "old signature failed: "+err.Error())
	}

	// sign the challenge with NEW (pending) private key (proves NEW ownership)
	newSigB64, err := signDataSecure(pendingPrivBuf, req.ChallengeToken)
	if err != nil {
		_ = keychain.DeletePendingPrivateKey(d.Store)
		_ = keychain.DeletePendingPublicKey(d.Store)
		return errs.CodeResponse(errs.ErrCodeCryptoFailure, "new signature failed: "+err.Error())
	}

	d.Logger.Println("rotate user keypair prepare successful (pending stored, both signatures generated)")
	return proto.BaseResponse{Success: true, Data: proto.RotateUserKeypairPrepareResponseData{
		NewPublicKey: keyPair.PublicKey,
		OldSignature: oldSigB64,
		NewSignature: newSigB64,
	}}
}

// HandleRotateUserKeypairPromote — promotes pending → active after verifying the server confirmation.
func HandleRotateUserKeypairPromote(d Deps, req proto.RotateUserKeypairPromoteRequest) proto.BaseResponse {
	d.Logger.Println("rotate user keypair promote request processing...")

	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}

	// Verify the signed confirmation payload with the server public key. The
	// payload contains the pending public-key hash and an expiry, so the
	// server Redis TTL / account binding semantics carry through to the
	// Keeper promote boundary.
	if ok, resp := verifyServerSig(d, req.ConfirmationPayload, req.ConfirmationSignature, req.ServerKeyVersion, "rotate keypair promote"); !ok {
		return resp
	}

	payload, err := parseRotateKeyConfirmationPayload(req.ConfirmationPayload)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeValidation, err.Error())
	}
	if payload.ConfirmationToken != req.ConfirmationToken {
		return errs.CodeResponse(errs.ErrCodeValidation, "confirmation token does not match signed payload")
	}
	if d.Now().Unix() > payload.ExpiresAt {
		return errs.CodeResponse(errs.ErrCodeCryptoFailure, "rotate-key confirmation expired")
	}

	// promote requires pending to exist
	if _, err := keychain.GetPendingPrivateKey(d.Store); err != nil {
		return errs.CodeResponse(errs.ErrCodeNotFound, "no pending keypair to promote (call prepare first)")
	}
	pendingPub, err := keychain.GetPendingPublicKey(d.Store)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeNotFound, "pending public key not found")
	}
	if payload.PendingPublicKeySHA256 != pendingPublicKeyHash(pendingPub) {
		return errs.CodeResponse(errs.ErrCodeCryptoFailure, "pending public key does not match signed confirmation")
	}

	promoted, err := keychain.PromotePendingKeypair(d.Store)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "promote pending keypair failed: "+err.Error())
	}
	if !promoted {
		return errs.CodeResponse(errs.ErrCodeNotFound, "no pending keypair to promote")
	}

	// New active public key in response — for caller (Extension) UI update / verification.
	activePub, err := keychain.GetPublicKey(d.Store)
	if err != nil {
		return errs.Response(err) // ErrSecretNotFound → not_found
	}

	d.Logger.Println("rotate user keypair promote successful (pending → active)")
	return proto.BaseResponse{Success: true, Data: proto.RotateUserKeypairPromoteResponseData{
		Promoted:        true,
		ActivePublicKey: activePub,
	}}
}

func parseRotateKeyConfirmationPayload(raw string) (rotateKeyConfirmationPayload, error) {
	var payload rotateKeyConfirmationPayload
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		return payload, err
	}
	if payload.Type != rotateKeyConfirmationPayloadType {
		return payload, errors.New("invalid rotate-key confirmation payload type")
	}
	if payload.ConfirmationToken == "" {
		return payload, errors.New("confirmation payload missing confirmation_token")
	}
	if payload.AccountID == "" {
		return payload, errors.New("confirmation payload missing account_id")
	}
	if payload.PendingPublicKeySHA256 == "" {
		return payload, errors.New("confirmation payload missing pending_public_key_sha256")
	}
	if payload.ExpiresAt <= 0 {
		return payload, errors.New("confirmation payload missing expires_at")
	}
	return payload, nil
}

func pendingPublicKeyHash(pendingPubPEM string) string {
	pendingPubB64 := base64.StdEncoding.EncodeToString([]byte(pendingPubPEM))
	sum := sha256.Sum256([]byte(pendingPubB64))
	return hex.EncodeToString(sum[:])
}
