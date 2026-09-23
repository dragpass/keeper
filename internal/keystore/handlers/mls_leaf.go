// mls_leaf.go — the MLS leaf declaration: producing one (mls_leaf_declare) and
// checking one (VerifyLeafDeclaration).
//
// Contract: dragpass-control-plane
// docs/exec-plans/active/dragpass-chat-v2-mls-integration.md §5.2, §5.3, §12.2.

package handlers

import (
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/base64"
	"errors"

	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/secure"
)

// HandleMLSLeafDeclare signs a declaration for this device's leaf key.
//
// enroll with no stored key mints one. enroll for the identity already stored
// signs a fresh declaration over the same key, so a response lost in transit
// costs a retry and not a rotation. rotate replaces the stored key for that
// same identity. A stored key for any other (account, device) is refused
// either way: rebinding it would let one device's key speak for another, and
// the way out is reset_device_identity.
//
// On rotate the new key is written only after the declaration is signed, so a
// failure leaves the old key and the declaration peers already hold in step.
func HandleMLSLeafDeclare(d Deps, req proto.MLSLeafDeclareRequest) proto.BaseResponse {
	d.Logger.Println("mls leaf declare request processing...")

	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}
	if ok, resp := verifyServerSig(d, req.ChallengeToken, req.ServerSignature, req.ServerKeyVersion, "mls leaf declare"); !ok {
		return resp
	}
	if rotatedAtTooFarAhead(d, req.NotBefore) {
		return errs.CodeResponse(errs.ErrCodeValidation, "not_before is too far in the future")
	}

	stored, found, err := keychain.GetMLSLeafKey(d.Store)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "mls leaf key record is unreadable")
	}
	defer secure.Zeroize(stored.SecretKey)
	if found && (stored.AccountID != req.AccountID || stored.DeviceID != req.DeviceID) {
		return errs.CodeResponse(errs.ErrCodeValidation,
			"an mls leaf key for a different account or device is stored; reset_device_identity first")
	}
	if !found && req.Reason == proto.MLSLeafReasonRotate {
		return errs.CodeResponse(errs.ErrCodeNotFound, "no mls leaf key to rotate; enroll first")
	}

	accountPriv, err := getPrivateKeySecure(d.Store)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeNotFound, "account keypair not found (signup required first)")
	}
	defer accountPriv.Destroy()

	leaf := stored
	mint := !found || req.Reason == proto.MLSLeafReasonRotate
	if mint {
		public, secret, err := ed25519.GenerateKey(d.Random())
		if err != nil {
			return errs.CodeResponse(errs.ErrCodeInternal, "mls leaf key generation failed")
		}
		defer secure.Zeroize(secret)
		leaf = keychain.MLSLeafKey{
			AccountID: req.AccountID,
			DeviceID:  req.DeviceID,
			SecretKey: secret,
			PublicKey: public,
		}
	}

	fingerprint, err := crypto.MLSLeafSignatureKeyFingerprint(leaf.PublicKey)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeInternal, "mls leaf key fingerprint failed")
	}
	declaration := proto.MLSLeafDeclaration{
		AccountID:               req.AccountID,
		DeviceID:                req.DeviceID,
		SignatureKey:            base64.StdEncoding.EncodeToString(leaf.PublicKey),
		SignatureKeyFingerprint: fingerprint,
		NotBefore:               req.NotBefore,
		Reason:                  req.Reason,
	}
	declaration.Signature, err = signDataSecure(accountPriv, declaration.Canonical())
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeCryptoFailure, "mls leaf declaration signing failed")
	}

	if mint {
		if err := keychain.SaveMLSLeafKey(d.Store, leaf); err != nil {
			return errs.CodeResponse(errs.ErrCodeStorageFailure, "mls leaf key could not be stored")
		}
	}

	d.Logger.Printf("mls leaf declare successful (reason=%s, new key=%t)", req.Reason, mint)
	return proto.BaseResponse{Success: true, Data: proto.MLSLeafDeclareResponseData{MLSLeafDeclaration: declaration}}
}

// VerifyLeafDeclaration checks a declaration against the account key it claims
// to be signed by. The caller is responsible for that key being the pinned one
// (§5.3 steps 3–4) and for comparing account_id / device_id / fingerprint with
// the leaf's credential and signature key (steps 6–7); this is step 5.
//
// The fingerprint is recomputed from the declared key rather than trusted, for
// the same reason verifyRotationStatement recomputes its own: otherwise a
// declaration could vouch for one key while carrying another.
func VerifyLeafDeclaration(decl proto.MLSLeafDeclaration, accountPublicKey *rsa.PublicKey) error {
	if accountPublicKey == nil {
		return errors.New("mls leaf declaration has no account key to verify against")
	}
	if err := decl.Validate(); err != nil {
		return err
	}
	signatureKey, err := base64.StdEncoding.DecodeString(decl.SignatureKey)
	if err != nil {
		return errors.New("mls leaf declaration signature_key is not Base64")
	}
	fingerprint, err := crypto.MLSLeafSignatureKeyFingerprint(signatureKey)
	if err != nil {
		return errors.New("mls leaf declaration signature_key is not a raw Ed25519 public key")
	}
	if fingerprint != decl.SignatureKeyFingerprint {
		return errors.New("mls leaf declaration fingerprint does not match its signature_key")
	}
	signature, err := base64.StdEncoding.DecodeString(decl.Signature)
	if err != nil {
		return errors.New("mls leaf declaration signature is not Base64")
	}
	if err := crypto.VerifySignature(accountPublicKey, decl.Canonical(), signature); err != nil {
		return errors.New("mls leaf declaration signature does not verify")
	}
	return nil
}
