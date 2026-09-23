// mls_leaf.go — the MLS leaf declaration: producing one (mls_leaf_declare) and
// checking one (VerifyLeafDeclaration).
//
// Contract: dragpass-control-plane
// docs/exec-plans/active/dragpass-chat-v2-mls-integration.md §5.2, §5.3, §12.2.

package handlers

import (
	"bytes"
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

// HandleMLSLeafDeclare mints a leaf key for this device and signs a
// declaration for it, into the pending slot.
//
// enroll needs no usable active key (a record an older Keeper wrote does not
// count); rotate needs one. Either way the new key and its declaration are
// written to the pending slot and the active slot is not touched, so a
// declaration the server never accepts cannot replace the one peers hold.
// mls_leaf_promote makes it active.
//
// While a pending entry exists, every declare returns that entry's declaration
// and mints nothing — whatever the challenge, reason or window of the retry.
// That is what makes a lost response harmless: the retry returns the key the
// server may already have accepted rather than a second one. It returns the
// stored bytes, signature included, and never re-signs: RSA-PSS is randomized,
// so a second signature would be a second declaration to the server.
// mls_leaf_abort is the only way to discard the pending entry.
//
// A stored key for any other (account, device) is refused: rebinding it would
// let one device's key speak for another, and the way out is
// reset_device_identity.
//
// The gate is the server signature plus a challenge bound to this purpose,
// account and device (requireMLSLeafChallenge); both run before the lock is
// taken. Everything from reading the slots to saving pending runs under
// keychain.WithMLSLeafLock, because two Keeper processes declaring at once
// would otherwise each mint a key and each return a different one.
func HandleMLSLeafDeclare(d Deps, req proto.MLSLeafDeclareRequest) proto.BaseResponse {
	d.Logger.Println("mls leaf declare request processing...")

	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}
	if ok, resp := verifyServerSig(d, req.ChallengeToken, req.ServerSignature, req.ServerKeyVersion, "mls leaf declare"); !ok {
		return resp
	}
	if resp, ok := requireMLSLeafChallenge(d, req); !ok {
		return resp
	}
	if rotatedAtTooFarAhead(d, req.NotBefore) {
		return errs.CodeResponse(errs.ErrCodeValidation, "not_before is too far in the future")
	}

	var (
		resp   proto.BaseResponse
		minted bool
	)
	lockErr := keychain.WithMLSLeafLock(d.Store, func() error {
		resp, minted = declareLocked(d, req)
		return nil
	})
	if lockErr != nil {
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "mls leaf lock could not be acquired")
	}
	if resp.Success {
		d.Logger.Printf("mls leaf declare successful (reason=%s, new key=%t)", req.Reason, minted)
	}
	return resp
}

// declareLocked is the critical section. Every keychain call in it reads or
// writes one slot directly; none of them takes WithMLSLeafLock, which would
// deadlock here (TestMLSLeafLifecycle_HoldsTheLockWithoutReentering).
func declareLocked(d Deps, req proto.MLSLeafDeclareRequest) (proto.BaseResponse, bool) {
	active, pending, resp, ok := loadMLSLeafSlots(d)
	if !ok {
		return resp, false
	}
	defer wipeMLSLeafSlots(active, pending)

	for _, stored := range []*keychain.MLSLeafKey{active, pending} {
		if stored != nil && (stored.AccountID != req.AccountID || stored.DeviceID != req.DeviceID) {
			return errs.CodeResponse(errs.ErrCodeValidation,
				"an mls leaf key for a different account or device is stored; reset_device_identity first"), false
		}
	}
	if pending != nil {
		decl, err := storedMLSLeafDeclaration(*pending)
		if err != nil {
			return errs.CodeResponse(errs.ErrCodeStorageFailure, "pending mls leaf declaration is unreadable"), false
		}
		return proto.BaseResponse{Success: true, Data: proto.MLSLeafDeclareResponseData{MLSLeafDeclaration: decl}}, false
	}

	if req.NotAfter <= d.Now().Unix() {
		return errs.CodeResponse(errs.ErrCodeValidation, "not_after has already passed"), false
	}
	live := active != nil && active.Usable()
	switch {
	case req.Reason == proto.MLSLeafReasonEnroll && live:
		return errs.CodeResponse(errs.ErrCodeValidation, "an mls leaf key is already active; rotate to replace it"), false
	case req.Reason == proto.MLSLeafReasonRotate && !live:
		return errs.CodeResponse(errs.ErrCodeNotFound, "no mls leaf key to rotate; enroll first"), false
	}

	accountPriv, err := getPrivateKeySecure(d.Store)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeNotFound, "account keypair not found (signup required first)"), false
	}
	defer accountPriv.Destroy()
	accountPublicKeyPEM, err := keychain.GetPublicKey(d.Store)
	if err != nil || accountPublicKeyPEM == "" {
		return errs.CodeResponse(errs.ErrCodeNotFound, "account public key not found (signup required first)"), false
	}

	public, secret, err := ed25519.GenerateKey(d.Random())
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeInternal, "mls leaf key generation failed"), false
	}
	defer secure.Zeroize(secret)
	fingerprint, err := crypto.MLSLeafSignatureKeyFingerprint(public)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeInternal, "mls leaf key fingerprint failed"), false
	}
	declaration := proto.MLSLeafDeclaration{
		AccountID:               req.AccountID,
		DeviceID:                req.DeviceID,
		SignatureKey:            base64.StdEncoding.EncodeToString(public),
		SignatureKeyFingerprint: fingerprint,
		NotBefore:               req.NotBefore,
		NotAfter:                req.NotAfter,
		Reason:                  req.Reason,
	}
	declaration.Signature, err = signDataSecure(accountPriv, declaration.Canonical())
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeCryptoFailure, "mls leaf declaration signing failed"), false
	}
	extension, err := proto.EncodeMLSLeafExtension(declaration, accountPublicKeyPEM)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeInternal, "mls leaf declaration could not be encoded"), false
	}
	if err := keychain.SaveMLSLeafPending(d.Store, keychain.MLSLeafKey{
		AccountID:   req.AccountID,
		DeviceID:    req.DeviceID,
		SecretKey:   secret,
		PublicKey:   public,
		Declaration: extension,
	}); err != nil {
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "mls leaf key could not be stored"), false
	}
	return proto.BaseResponse{Success: true, Data: proto.MLSLeafDeclareResponseData{MLSLeafDeclaration: declaration}}, true
}

// HandleMLSLeafPromote makes the pending entry active once ariadne's signed
// acceptance names it.
//
// The token must name exactly the pending entry — account, device,
// fingerprint, not_before and not_after. Then pending is copied over active in
// one keyring write, and the pending slot is emptied. A token naming the
// current active entry instead is a duplicate promote (a retry after a lost
// response) and succeeds without writing. Anything else is refused and changes
// nothing.
//
// The pending slot is emptied after the active write, as a second step. A
// crash between the two leaves a pending entry identical to the active one;
// loadMLSLeafSlots recognises that and drops it, so it never reads as a
// declaration still waiting for the server.
func HandleMLSLeafPromote(d Deps, req proto.MLSLeafPromoteRequest) proto.BaseResponse {
	d.Logger.Println("mls leaf promote request processing...")

	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}
	if ok, resp := verifyServerSig(d, req.AcceptanceToken, req.ServerSignature, req.ServerKeyVersion, "mls leaf promote"); !ok {
		return resp
	}
	accepted, err := proto.ParseMLSLeafAccepted(req.AcceptanceToken)
	if err != nil {
		return errs.Response(err)
	}

	var resp proto.BaseResponse
	lockErr := keychain.WithMLSLeafLock(d.Store, func() error {
		resp = promoteLocked(d, accepted)
		return nil
	})
	if lockErr != nil {
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "mls leaf lock could not be acquired")
	}
	if resp.Success {
		d.Logger.Printf("mls leaf promote successful (promoted=%t)", resp.Data.(proto.MLSLeafPromoteResponseData).Promoted)
	}
	return resp
}

func promoteLocked(d Deps, accepted proto.MLSLeafAccepted) proto.BaseResponse {
	active, pending, resp, ok := loadMLSLeafSlots(d)
	if !ok {
		return resp
	}
	defer wipeMLSLeafSlots(active, pending)

	if pending != nil {
		decl, err := storedMLSLeafDeclaration(*pending)
		if err != nil {
			return errs.CodeResponse(errs.ErrCodeStorageFailure, "pending mls leaf declaration is unreadable")
		}
		if accepted.Names(decl) {
			if err := keychain.SaveMLSLeafKey(d.Store, *pending); err != nil {
				return errs.CodeResponse(errs.ErrCodeStorageFailure, "mls leaf key could not be promoted")
			}
			if _, err := keychain.DeleteMLSLeafPending(d.Store); err != nil {
				d.Logger.Println("mls leaf promote: the pending slot could not be emptied; it now equals the active one")
			}
			return proto.BaseResponse{Success: true, Data: proto.MLSLeafPromoteResponseData{
				Promoted: true, Fingerprint: decl.SignatureKeyFingerprint,
			}}
		}
	}
	if active != nil && active.Usable() {
		decl, err := storedMLSLeafDeclaration(*active)
		if err != nil {
			return errs.CodeResponse(errs.ErrCodeStorageFailure, "active mls leaf declaration is unreadable")
		}
		if accepted.Names(decl) {
			return proto.BaseResponse{Success: true, Data: proto.MLSLeafPromoteResponseData{
				Promoted: false, Fingerprint: decl.SignatureKeyFingerprint,
			}}
		}
	}
	return errs.CodeResponse(errs.ErrCodeValidation, "acceptance_token names neither the pending nor the active mls leaf")
}

// HandleMLSLeafAbort discards the pending entry. Idempotent. The active entry
// is never touched.
func HandleMLSLeafAbort(d Deps, req proto.MLSLeafAbortRequest) proto.BaseResponse {
	d.Logger.Println("mls leaf abort request processing...")
	var (
		aborted bool
		failed  bool
	)
	lockErr := keychain.WithMLSLeafLock(d.Store, func() error {
		var err error
		aborted, err = keychain.DeleteMLSLeafPending(d.Store)
		failed = err != nil
		return nil
	})
	if lockErr != nil {
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "mls leaf lock could not be acquired")
	}
	if failed {
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "pending mls leaf key could not be removed")
	}
	d.Logger.Printf("mls leaf abort successful (aborted=%t)", aborted)
	return proto.BaseResponse{Success: true, Data: proto.MLSLeafAbortResponseData{Aborted: aborted}}
}

// HandleMLSLeafStatus reports which entries exist, by signature key
// fingerprint and validity window. No secret, and no declaration, leaves
// through it. A pending entry the server will no longer accept is reported
// like any other; whether to abort it is the caller's decision.
func HandleMLSLeafStatus(d Deps, req proto.MLSLeafStatusRequest) proto.BaseResponse {
	var resp proto.BaseResponse
	lockErr := keychain.WithMLSLeafLock(d.Store, func() error {
		active, pending, failure, ok := loadMLSLeafSlots(d)
		if !ok {
			resp = failure
			return nil
		}
		defer wipeMLSLeafSlots(active, pending)
		var data proto.MLSLeafStatusResponseData
		if active != nil && active.Usable() {
			decl, err := storedMLSLeafDeclaration(*active)
			if err != nil {
				resp = errs.CodeResponse(errs.ErrCodeStorageFailure, "active mls leaf declaration is unreadable")
				return nil
			}
			data.HasActive = true
			data.ActiveFingerprint = decl.SignatureKeyFingerprint
			data.ActiveNotAfter = decl.NotAfter
		}
		if pending != nil {
			decl, err := storedMLSLeafDeclaration(*pending)
			if err != nil {
				resp = errs.CodeResponse(errs.ErrCodeStorageFailure, "pending mls leaf declaration is unreadable")
				return nil
			}
			data.HasPending = true
			data.PendingFingerprint = decl.SignatureKeyFingerprint
			data.PendingNotBefore = decl.NotBefore
			data.PendingNotAfter = decl.NotAfter
		}
		resp = proto.BaseResponse{Success: true, Data: data}
		return nil
	})
	if lockErr != nil {
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "mls leaf lock could not be acquired")
	}
	return resp
}

// loadMLSLeafSlots reads both slots; the caller holds the lock. A nil pointer
// is an empty slot. A pending entry holding the active key is what an
// interrupted promote leaves behind, and it is removed here rather than
// reported, so it can never be mistaken for a declaration the server has not
// seen.
func loadMLSLeafSlots(d Deps) (active, pending *keychain.MLSLeafKey, resp proto.BaseResponse, ok bool) {
	a, foundActive, err := keychain.GetMLSLeafKey(d.Store)
	if err != nil {
		return nil, nil, errs.CodeResponse(errs.ErrCodeStorageFailure, "mls leaf key record is unreadable"), false
	}
	p, foundPending, err := keychain.GetMLSLeafPending(d.Store)
	if err != nil {
		secure.Zeroize(a.SecretKey)
		return nil, nil, errs.CodeResponse(errs.ErrCodeStorageFailure, "pending mls leaf key record is unreadable"), false
	}
	if foundActive {
		active = &a
	}
	if foundPending {
		pending = &p
	}
	if active != nil && pending != nil && active.Usable() && bytes.Equal(active.PublicKey, pending.PublicKey) {
		if _, err := keychain.DeleteMLSLeafPending(d.Store); err != nil {
			secure.Zeroize(a.SecretKey)
			secure.Zeroize(p.SecretKey)
			return nil, nil, errs.CodeResponse(errs.ErrCodeStorageFailure, "pending mls leaf key could not be removed"), false
		}
		secure.Zeroize(p.SecretKey)
		pending = nil
	}
	return active, pending, proto.BaseResponse{}, true
}

func wipeMLSLeafSlots(slots ...*keychain.MLSLeafKey) {
	for _, slot := range slots {
		if slot != nil {
			secure.Zeroize(slot.SecretKey)
		}
	}
}

// storedMLSLeafDeclaration reads back the declaration a record carries,
// through the same strict decoder a peer's verifier uses.
func storedMLSLeafDeclaration(key keychain.MLSLeafKey) (proto.MLSLeafDeclaration, error) {
	ext, err := decodeMLSLeafExtension(key.Declaration)
	if err != nil {
		return proto.MLSLeafDeclaration{}, err
	}
	return ext.Declaration, nil
}

// mlsLeafChallengeClockSkewSeconds matches the future-issue tolerance of the
// chat permits (chatStatePermitClockSkewSeconds). The token carries no issue
// time, but the issuer sets expires_at to it plus the TTL, so an expiry further
// out than TTL + skew is a token issued in the future.
const mlsLeafChallengeClockSkewSeconds = 5

// requireMLSLeafChallenge binds the verified token to this request. Expiry has
// no grace, as with the chat permits: at expires_at the token is dead.
func requireMLSLeafChallenge(d Deps, req proto.MLSLeafDeclareRequest) (proto.BaseResponse, bool) {
	return requirePurposeChallenge(d, req.ChallengeToken, req.AccountID, req.DeviceID,
		proto.ParseMLSLeafChallenge, proto.MLSLeafChallengeTTLSeconds)
}

// requirePurposeChallenge is the rule both MLS challenges share, after the
// server signature has verified: parse holds the exact field count, domain and
// version; then the request's account and device, and an expiry that has not
// passed on the Keeper clock nor lies further out than TTL + skew.
func requirePurposeChallenge(
	d Deps, token, accountID, deviceID string,
	parse func(string) (proto.MLSLeafChallenge, error), ttlSeconds int64,
) (proto.BaseResponse, bool) {
	challenge, err := parse(token)
	if err != nil {
		return errs.Response(err), false
	}
	if challenge.AccountID != accountID || challenge.DeviceID != deviceID {
		return errs.CodeResponse(errs.ErrCodeValidation, "challenge_token was issued for a different account or device"), false
	}
	now := d.Now().Unix()
	if now >= challenge.ExpiresAt {
		return errs.CodeResponse(errs.ErrCodeValidation, "challenge_token has expired"), false
	}
	if challenge.ExpiresAt > now+ttlSeconds+mlsLeafChallengeClockSkewSeconds {
		return errs.CodeResponse(errs.ErrCodeValidation, "challenge_token expires too far in the future"), false
	}
	return proto.BaseResponse{}, true
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
