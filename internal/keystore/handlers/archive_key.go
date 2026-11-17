// archive_key.go — per-org Archive / Recovery keypair handlers.
//
// HandleArchiveKeyGenerate / HandleArchiveKeyStatus manage the lifecycle of the
// RSA keypair used as the org break-glass recovery key. During group DEK
// rotation the OLD Group DEK is additionally wrapped to this key's public half
// (an org_owner_archive grant), so the org owner can recover past DEKs as a
// defense-in-depth / break-glass path.
//
// The private key lives only in the org_archive_private_key keychain slot,
// wrapped in memguard during the save window, and is never used for identity /
// login / recovery / request signing. It never leaves the slot.

package handlers

import (
	"encoding/base64"
	"errors"

	"github.com/awnumar/memguard"

	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/secure"
)

// HandleArchiveKeyGenerate generates a new RSA archive keypair if none exists.
//
// Idempotent: when an active archive key is already present, no new key is
// created and only the existing key's meta (public key + fingerprint) is
// returned.
func HandleArchiveKeyGenerate(d Deps, req proto.ArchiveKeyGenerateRequest) proto.BaseResponse {
	d.Logger.Println("archive key generate processing...")

	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}
	if req.OrgID != "" {
		return generateOrgArchiveKey(d, req.OrgID)
	}

	// If an active archive key already exists, return only its meta.
	if existing, err := keychain.GetArchivePublicKey(d.Store); err == nil && existing != "" {
		d.Logger.Println("archive key generate: active key already present, returning meta")
		return proto.BaseResponse{Success: true, Data: proto.ArchiveKeyGenerateResponseData{
			PublicKey:   existing,
			Fingerprint: fingerprintBase64Public(existing),
		}}
	}

	keyPair, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		d.Logger.Printf("archive key generate: keygen failed: %v", err)
		return errs.CodeResponse(errs.ErrCodeInternal, "archive key keygen failed: "+err.Error())
	}

	// Protect the private key PEM in memguard, save to the keystore, then wipe.
	privKeyBuf := memguard.NewBufferFromBytes([]byte(keyPair.PrivateKey))
	secure.WipeString(&keyPair.PrivateKey)
	defer privKeyBuf.Destroy()

	if err := keychain.SaveArchivePrivateKey(d.Store, string(privKeyBuf.Bytes())); err != nil {
		d.Logger.Printf("archive key generate: save priv failed: %v", err)
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "save archive priv key failed: "+err.Error())
	}
	if err := keychain.SaveArchivePublicKey(d.Store, keyPair.PublicKey); err != nil {
		d.Logger.Printf("archive key generate: save pub failed: %v", err)
		// Partial failure — only priv is saved. The next generate call sees
		// GetArchivePublicKey as empty and regenerates, overwriting the priv
		// slot, so it never gets stuck.
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "save archive pub key failed: "+err.Error())
	}

	d.Logger.Println("archive key generate: new rsa keypair saved")
	return proto.BaseResponse{Success: true, Data: proto.ArchiveKeyGenerateResponseData{
		PublicKey:   keyPair.PublicKey,
		Fingerprint: fingerprintBase64Public(keyPair.PublicKey),
	}}
}

// archiveSlotProcessLock and archiveKeyPairGenerator are the keychain
// process lock and the RSA generator the org generate uses; tests replace
// them to observe the order.
var (
	archiveSlotProcessLock  = keychain.WithKeychainProcessLock
	archiveKeyPairGenerator = crypto.GenerateRSAKeyPair
)

// generateOrgArchiveKey is the org_id form of archive_key_generate (lv96). It
// reads and writes only the org's own slots; another org's slot and the
// device-wide slot are never read or written.
//
// The whole call runs under archiveSplitPreparationMu, the mutex the split,
// finalize and rotation writers of the org archive slots hold; the re-check
// and the writes also run inside the keychain process lock (lock order: the
// mutex, then the process lock; no holder of the process lock takes the
// mutex), which is not held while the RSA pair is generated. Two generates
// for one org therefore cannot interleave their writes or roll back each
// other's key, in one process or across processes.
//
// Slot states:
//   - public and private present: the org's key, returned unchanged;
//   - a staged rotation for the org: refused (archive_key_rotation_pending);
//   - private without public (an interrupted write): refused
//     (archive_key_slot_incomplete), never overwritten;
//   - public without private (a quorum split finalized): refused
//     (archive_key_private_absent), not reported as a usable key;
//   - neither: a new pair is written, private first; a failed public write
//     removes the private half again.
func generateOrgArchiveKey(d Deps, orgID string) proto.BaseResponse {
	archiveSplitPreparationMu.Lock()
	defer archiveSplitPreparationMu.Unlock()

	// The keychain process lock is not held across RSA generation: another
	// Keeper process waits for it at most five seconds
	// (keychain.withPersonalKeyBundleLock). The state is read first, the pair
	// generated outside the lock, and the lock covers only the re-check and
	// the writes.
	if resp, decided, err := orgArchiveSlotDecision(d, orgID); err != nil {
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "read archive key failed")
	} else if decided {
		return resp
	}
	keyPair, err := archiveKeyPairGenerator()
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeInternal, "archive key keygen failed")
	}
	privKeyBuf := memguard.NewBufferFromBytes([]byte(keyPair.PrivateKey))
	secure.WipeString(&keyPair.PrivateKey)
	defer privKeyBuf.Destroy()

	var resp proto.BaseResponse
	if err := archiveSlotProcessLock(d.Store, func() error {
		decision, decided, err := orgArchiveSlotDecision(d, orgID)
		if err != nil {
			resp = errs.CodeResponse(errs.ErrCodeStorageFailure, "read archive key failed")
			return nil
		}
		if decided {
			// Another process wrote or staged the org's key meanwhile; the
			// new pair is dropped.
			resp = decision
			return nil
		}
		resp = writeOrgArchiveKey(d, keychain.OrgArchiveActiveSlot(orgID), privKeyBuf.Bytes(), keyPair.PublicKey)
		return nil
	}); err != nil {
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "archive key lock unavailable")
	}
	return resp
}

// slotHalves reports a slot's public key and whether its private key is
// present. The private PEM is wiped as soon as its presence is known.
func slotHalves(store keychain.SecretStore, slot keychain.ArchiveKeySlot) (string, bool, error) {
	pub, err := slot.GetPublic(store)
	if err != nil && !errors.Is(err, keychain.ErrSecretNotFound) {
		return "", false, err
	}
	priv, err := slot.GetPrivate(store)
	if err != nil && !errors.Is(err, keychain.ErrSecretNotFound) {
		return "", false, err
	}
	hasPriv := priv != ""
	secure.WipeString(&priv)
	return pub, hasPriv, nil
}

// orgArchiveSlotDecision reads the org's slots. decided is true when the
// state already answers the call: the existing key, or a refusal.
func orgArchiveSlotDecision(d Deps, orgID string) (proto.BaseResponse, bool, error) {
	slot := keychain.OrgArchiveActiveSlot(orgID)
	stagedPub, stagedPriv, err := slotHalves(d.Store, keychain.OrgArchiveStagingSlot(orgID))
	if err != nil {
		return proto.BaseResponse{}, false, err
	}
	if stagedPub != "" || stagedPriv {
		return errs.CodeResponse(errs.ErrCodeArchiveKeyRotationPending, "an archive key rotation is staged for this org"), true, nil
	}
	existing, hasPriv, err := slotHalves(d.Store, slot)
	if err != nil {
		return proto.BaseResponse{}, false, err
	}
	switch {
	case existing != "" && hasPriv:
		d.Logger.Println("archive key generate: org key already present, returning meta")
		return proto.BaseResponse{Success: true, Data: proto.ArchiveKeyGenerateResponseData{
			PublicKey: existing, Fingerprint: fingerprintBase64Public(existing), Scope: slot.Scope,
		}}, true, nil
	case existing == "" && hasPriv:
		return errs.CodeResponse(errs.ErrCodeArchiveKeySlotIncomplete, "the org archive key slot holds a private key without its public key"), true, nil
	case existing != "" && !hasPriv:
		return errs.CodeResponse(errs.ErrCodeArchiveKeyPrivateAbsent, "the org archive key has no private key on this device"), true, nil
	}
	return proto.BaseResponse{}, false, nil
}

// writeOrgArchiveKey writes a new pair, private first; a failed public write
// removes the private half again.
func writeOrgArchiveKey(d Deps, slot keychain.ArchiveKeySlot, privatePEM []byte, publicPEM string) proto.BaseResponse {
	if err := slot.SavePrivate(d.Store, string(privatePEM)); err != nil {
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "save archive private key failed")
	}
	if err := slot.SavePublic(d.Store, publicPEM); err != nil {
		if delErr := slot.DeletePrivate(d.Store); delErr != nil && !errors.Is(delErr, keychain.ErrSecretNotFound) {
			d.Logger.Println("archive key generate: removing the unpublished org private key failed")
		}
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "save archive public key failed")
	}
	d.Logger.Println("archive key generate: new org rsa keypair saved")
	return proto.BaseResponse{Success: true, Data: proto.ArchiveKeyGenerateResponseData{
		PublicKey: publicPEM, Fingerprint: fingerprintBase64Public(publicPEM), Scope: slot.Scope,
	}}
}

// HandleArchiveKeyStatus reports active archive key presence + public key +
// fingerprint. Absence is normal (org has not enabled archive keys yet), so it
// returns 200 with has_active=false. With org_id it reports the org's own key,
// else the device-wide one the org still uses.
func HandleArchiveKeyStatus(d Deps, req proto.ArchiveKeyStatusRequest) proto.BaseResponse {
	d.Logger.Println("archive key status processing...")

	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}

	slot, pub, found, err := keychain.FindArchiveKey(d.Store, keychain.OrgArchiveActiveCandidates(req.OrgID))
	if err != nil {
		d.Logger.Printf("archive key status: read active key failed: %v", err)
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "read archive key failed")
	}
	data := proto.ArchiveKeyStatusResponseData{}
	if found {
		data.HasActive = true
		data.PublicKey = pub
		data.Fingerprint = fingerprintBase64Public(pub)
		data.Scope = slot.Scope
	}
	if _, stagedPub, staged, err := keychain.FindArchiveKey(d.Store, keychain.OrgArchiveStagingCandidates(req.OrgID)); err == nil && staged {
		data.StagingFingerprint = fingerprintBase64Public(stagedPub)
	}
	return proto.BaseResponse{Success: true, Data: data}
}

// archiveUnwrapWithSlot fetches a private key with getKey, parses it, and
// RSA-OAEP-decrypts encrypted. Helper for HandleArchiveUnwrapAndRewrap's
// slot fallback; each error keeps its source so the caller can decide whether
// falling back makes sense.
func archiveUnwrapWithSlot(
	d Deps,
	getKey func(keychain.SecretStore) (*memguard.LockedBuffer, error),
	encrypted []byte,
	gc *proto.GrantContext,
) ([]byte, error) {
	privKeyBuf, err := getKey(d.Store)
	if err != nil {
		return nil, err
	}
	defer privKeyBuf.Destroy()

	privKey, err := crypto.ParsePrivateKey(string(privKeyBuf.Bytes()))
	if err != nil {
		return nil, err
	}
	return unwrapGrant(privKey, encrypted, gc)
}

// unwrapWithOrgArchiveKey tries each org archive slot that may hold orgID's
// key, most specific first. Trying a wrong key costs one failed RSA-OAEP
// decrypt and reveals nothing. The returned error is the first slot's that
// held a key, or ErrSecretNotFound when none did.
func unwrapWithOrgArchiveKey(d Deps, orgID string, encrypted []byte, gc *proto.GrantContext) ([]byte, error) {
	var firstErr error
	for _, slot := range keychain.OrgArchiveActiveCandidates(orgID) {
		groupDEK, err := archiveUnwrapWithSlot(d, func(store keychain.SecretStore) (*memguard.LockedBuffer, error) {
			return getArchiveSlotPrivateKeySecure(store, slot)
		}, encrypted, gc)
		if err == nil {
			return groupDEK, nil
		}
		if firstErr == nil && !errors.Is(err, keychain.ErrSecretNotFound) {
			firstErr = err
		}
	}
	if firstErr == nil {
		return nil, keychain.ErrSecretNotFound
	}
	return nil, firstErr
}

// HandleArchiveUnwrapAndRewrap is the break-glass re-grant composite. It
// unwraps an OLD Group DEK that was wrapped to the org archive public key
// (org_owner_archive grant) with the archive private key, then re-wraps it to
// a target member's public key. The raw Group DEK lives only briefly in Keeper
// memory and is never in the response — same raw-free pattern as
// HandleDEKRewrapForMember. The archive private key never leaves its slot.
//
// Unwrap tries the ORG archive slots first (the org's own when org_id is set,
// then the device-wide one), then falls back to the ACCOUNT archive slot: after an ownership handoff, grants are re-wrapped to the new
// owner's account directory key, which lives in the account slot, while the
// org slot may hold an unrelated key (or none). Both slots failing surfaces
// the org-slot error (not_found when neither slot has a key).
func HandleArchiveUnwrapAndRewrap(d Deps, req proto.ArchiveUnwrapAndRewrapRequest) proto.BaseResponse {
	deny := func() proto.BaseResponse {
		return errs.CodeResponse(errs.ErrCodeNotFound, "archive regrant unavailable")
	}
	if req.Decision == nil {
		return deny()
	}
	context, _, _, err := archiveRewrapCommitments(req)
	if err != nil {
		return deny()
	}
	deadline, err := verifyAndConsumeGroupRewrapDecision(d, *req.Decision, context)
	if err != nil {
		return deny()
	}
	if !archiveRotationStageMatches(d, req) {
		return deny()
	}
	response := archiveUnwrapAndRewrap(d, req)
	now := d.Now()
	if response.Success && (now.Unix() >= req.Decision.ExpiresAt || !now.Before(deadline)) {
		return deny()
	}
	return response
}

func archiveUnwrapAndRewrap(d Deps, req proto.ArchiveUnwrapAndRewrapRequest) proto.BaseResponse {
	d.Logger.Println("archive unwrap and rewrap request processing...")

	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}

	recipientPubKey, err := crypto.ParsePublicKey(req.RecipientPublicKey)
	if err != nil {
		d.Logger.Printf("archive unwrap and rewrap error: failed to parse recipient public key: %v", err)
		return errs.CodeResponse(errs.ErrCodeValidation, "failed to parse recipient public key: "+err.Error())
	}

	// A re-grant naming the member's account is judged by that member's pin
	// before the archive key is touched, as dek_rewrap_for_member is.
	if req.RecipientAccountID != "" {
		// The owner's own active key is judged as self; the owner binding
		// is still checked (archiveRegrantPinAccount).
		pinAccount, selfResp, ok := archiveRegrantPinAccount(d, req.OwnerAccountID, req.RecipientAccountID, recipientPubKey)
		if !ok {
			return selfResp
		}
		if _, pinResp, ok := enforcePeerKeyPins(d, req.OwnerAccountID, []peerKeyPinCheck{{
			accountID:          pinAccount,
			observed:           crypto.AccountKeyFingerprint([]byte(req.RecipientPublicKey)),
			publicKey:          req.RecipientPublicKey,
			statements:         req.RotationStatements,
			enrollmentEvidence: req.EnrollmentEvidence,
		}}); !ok {
			return pinResp
		}
	}

	encrypted, err := base64.StdEncoding.DecodeString(req.WrappedForArchiveB64)
	if err != nil {
		d.Logger.Printf("archive unwrap and rewrap error: failed to decode wrapped_for_archive_b64: %v", err)
		return errs.CodeResponse(errs.ErrCodeValidation, "failed to decode wrapped_for_archive_b64: "+err.Error())
	}

	groupDEK, orgErr := unwrapWithOrgArchiveKey(d, req.OrgID, encrypted, req.GrantContext)
	if orgErr != nil {
		var accErr error
		groupDEK, accErr = archiveUnwrapWithSlot(d, GetAccountArchivePrivateKeySecure, encrypted, req.GrantContext)
		if accErr != nil {
			d.Logger.Printf("archive unwrap and rewrap error: org slot: %v; account slot: %v", orgErr, accErr)
			// Neither slot worked. Prefer the org-slot error for the coarse
			// code: missing org slot stays not_found (re-bootstrap signal);
			// an org-slot decrypt failure is crypto_failure.
			if resp := errs.Response(orgErr); resp.ErrorCode == string(errs.ErrCodeNotFound) {
				return resp
			}
			return grantOpenFailure(req.GrantContext, orgErr)
		}
		d.Logger.Println("archive unwrap and rewrap: org slot failed, account archive slot succeeded (handoff-received grant)")
	}
	defer secure.Zeroize(groupDEK)

	if len(groupDEK) != 32 {
		return errs.CodeResponse(errs.ErrCodeCryptoFailure, errors.New("unexpected group dek length (want 32)").Error())
	}

	newEncrypted, err := wrapGrant(recipientPubKey, groupDEK, req.GrantContext)
	if err != nil {
		d.Logger.Printf("archive unwrap and rewrap error: RSA-OAEP encrypt failed: %v", err)
		return errs.CodeResponse(errs.ErrCodeCryptoFailure, "RSA-OAEP encrypt failed: "+err.Error())
	}

	newEncryptedB64 := base64.StdEncoding.EncodeToString(newEncrypted)
	d.Logger.Println("archive unwrap and rewrap successful (raw group dek never left Keeper)")
	return proto.BaseResponse{Success: true, Data: proto.ArchiveUnwrapAndRewrapResponseData{
		EncryptedForOtherB64: newEncryptedB64,
	}}
}
