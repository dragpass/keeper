// rotate_request_key.go — per-device request-signing key rotation.
//
// 3-step flow:
//   1. Prepare: generate new Ed25519 keypair → save into pending slot, sign
//      challenge_token with both OLD and NEW priv. ACTIVE stays unchanged
//      (sign_request keeps working until the server moves it to retiring).
//   2. Promote: pending → active promotion, OLD discarded. Called by the
//      Extension after the server confirms rotation success.
//   3. Abort: force-discard the pending slot (idempotent). Cleanup path when
//      complete fails after prepare.

package handlers

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/secure"
)

// HandleRotateRequestKeyPrepare — rotation step 1.
//
// Steps:
//  1. fetch OLD priv from ACTIVE slot. If missing → not_found (enroll required before rotation).
//  2. generate new Ed25519 keypair → save in pending slot.
//  3. sign challenge_token with OLD priv → old_signature.
//  4. sign challenge_token with NEW priv → new_signature.
//  5. response: { new_public_key, old_signature, new_signature, old_key_id (=fingerprint) }.
//
// Force-overwrites a leftover pending slot — if prepare comes in again
// without an abort call, it does not get stuck.
func HandleRotateRequestKeyPrepare(d Deps, req proto.RotateRequestKeyPrepareRequest) proto.BaseResponse {
	d.Logger.Println("rotate request key prepare processing...")

	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}

	// 1) OLD priv.
	oldPrivB64, err := keychain.GetRequestSigningPrivateKey(d.Store)
	if err != nil || oldPrivB64 == "" {
		d.Logger.Println("rotate prepare: no active request key — enroll first")
		return errs.CodeResponse(errs.ErrCodeNotFound, "no active request signing key. enroll first")
	}
	oldPriv, err := decodeEd25519Private(oldPrivB64)
	if err != nil {
		d.Logger.Printf("rotate prepare: stored OLD priv corrupt: %v", err)
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "stored old request priv key corrupt")
	}
	defer secure.Zeroize(oldPriv)

	oldPubB64, _ := keychain.GetRequestSigningPublicKey(d.Store)

	// 2) generate NEW keypair + save into pending slot.
	newPub, newPriv, err := ed25519.GenerateKey(d.Random())
	if err != nil {
		d.Logger.Printf("rotate prepare: ed25519 keygen failed: %v", err)
		return errs.CodeResponse(errs.ErrCodeInternal, "request key keygen failed: "+err.Error())
	}
	defer secure.Zeroize(newPriv)

	newPubB64 := base64.StdEncoding.EncodeToString(newPub)
	newPrivB64 := base64.StdEncoding.EncodeToString(newPriv)
	defer secure.WipeString(&newPrivB64)

	if err := keychain.SavePendingRequestSigningPrivateKey(d.Store, newPrivB64); err != nil {
		d.Logger.Printf("rotate prepare: save pending priv failed: %v", err)
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "save pending priv key failed: "+err.Error())
	}
	if err := keychain.SavePendingRequestSigningPublicKey(d.Store, newPubB64); err != nil {
		d.Logger.Printf("rotate prepare: save pending pub failed: %v", err)
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "save pending pub key failed: "+err.Error())
	}

	// 3) OLD signature.
	oldSig := ed25519.Sign(oldPriv, []byte(req.ChallengeToken))
	// 4) NEW signature.
	newSig := ed25519.Sign(newPriv, []byte(req.ChallengeToken))

	d.Logger.Println("rotate prepare: pending key saved + OLD/NEW signatures produced")
	return proto.BaseResponse{Success: true, Data: proto.RotateRequestKeyPrepareResponseData{
		NewPublicKey: newPubB64,
		OldSignature: base64.StdEncoding.EncodeToString(oldSig),
		NewSignature: base64.StdEncoding.EncodeToString(newSig),
		OldKeyID:     fingerprintBase64Public(oldPubB64),
	}}
}

// HandleRotateRequestKeyPromote — rotation step 2.
//
// pending → active promotion. OLD slot is overwritten (untouched otherwise).
// If pending is absent → invalid_state.
func HandleRotateRequestKeyPromote(d Deps, req proto.RotateRequestKeyPromoteRequest) proto.BaseResponse {
	d.Logger.Println("rotate request key promote processing...")

	pendingPrivB64, err := keychain.GetPendingRequestSigningPrivateKey(d.Store)
	if err != nil || pendingPrivB64 == "" {
		d.Logger.Println("rotate promote: no pending request key")
		return errs.CodeResponse(errs.ErrCodeValidation, "no pending request signing key to promote")
	}
	pendingPubB64, err := keychain.GetPendingRequestSigningPublicKey(d.Store)
	if err != nil || pendingPubB64 == "" {
		d.Logger.Printf("rotate promote: pending priv exists but pub missing: %v", err)
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "pending request pub key missing")
	}

	// active slot overwrite — promote itself is not atomic, so a partial
	// failure (priv updated, pub not) can stick. If the two slots mismatch,
	// sign_request fails and middleware verify rejects → user restarts rotation.
	if err := keychain.SaveRequestSigningPrivateKey(d.Store, pendingPrivB64); err != nil {
		d.Logger.Printf("rotate promote: save active priv failed: %v", err)
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "promote priv failed: "+err.Error())
	}
	if err := keychain.SaveRequestSigningPublicKey(d.Store, pendingPubB64); err != nil {
		d.Logger.Printf("rotate promote: save active pub failed: %v", err)
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "promote pub failed: "+err.Error())
	}
	// clean up pending slot (best-effort).
	if err := keychain.DeletePendingRequestSigningPrivateKey(d.Store); err != nil {
		d.Logger.Printf("rotate promote: cleanup pending priv warn: %v", err)
	}
	if err := keychain.DeletePendingRequestSigningPublicKey(d.Store); err != nil {
		d.Logger.Printf("rotate promote: cleanup pending pub warn: %v", err)
	}

	d.Logger.Println("rotate promote: pending → active promotion complete")
	return proto.BaseResponse{Success: true, Data: proto.RotateRequestKeyPromoteResponseData{
		Promoted:        true,
		ActivePublicKey: pendingPubB64,
		Fingerprint:     fingerprintBase64Public(pendingPubB64),
	}}
}

// HandleRotateRequestKeyAbort — rotation step 3 (cleanup).
// Force-discard the pending slot. If both are absent → aborted=false (idempotent).
func HandleRotateRequestKeyAbort(d Deps, req proto.RotateRequestKeyAbortRequest) proto.BaseResponse {
	d.Logger.Println("rotate request key abort processing...")

	deletedAny := false
	if v, _ := keychain.GetPendingRequestSigningPrivateKey(d.Store); v != "" {
		if err := keychain.DeletePendingRequestSigningPrivateKey(d.Store); err != nil {
			d.Logger.Printf("rotate abort: delete pending priv failed: %v", err)
			return errs.CodeResponse(errs.ErrCodeStorageFailure, "abort priv delete failed: "+err.Error())
		}
		deletedAny = true
	}
	if v, _ := keychain.GetPendingRequestSigningPublicKey(d.Store); v != "" {
		if err := keychain.DeletePendingRequestSigningPublicKey(d.Store); err != nil {
			d.Logger.Printf("rotate abort: delete pending pub failed: %v", err)
			return errs.CodeResponse(errs.ErrCodeStorageFailure, "abort pub delete failed: "+err.Error())
		}
		deletedAny = true
	}

	d.Logger.Printf("rotate abort: aborted=%v", deletedAny)
	return proto.BaseResponse{Success: true, Data: proto.RotateRequestKeyAbortResponseData{
		Aborted: deletedAny,
	}}
}

// decodeEd25519Private — base64 → ed25519.PrivateKey (64B). Returns a non-nil
// error on wrong length / decode failure.
func decodeEd25519Private(b64 string) (ed25519.PrivateKey, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}
	if len(raw) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("ed25519 private key length=%d want %d",
			len(raw), ed25519.PrivateKeySize)
	}
	return ed25519.PrivateKey(raw), nil
}

// Avoid an unused-import warning since errs's sentinels aren't directly used here.
var _ = errors.New
