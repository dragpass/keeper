// archive_key_rotate.go — same-device org archive key rotation via a staging
// slot.
//
// archive_key_generate is idempotent (returns the existing key when one is
// present), so on the same device it can never mint a genuinely new key. Real
// rotation needs the OLD key to stay live while existing grants are re-wrapped
// to the NEW key, so it is split across three actions:
//
//   - HandleArchiveKeyRotateBegin  : generate a NEW keypair into the staging
//     slot, leaving the active slot untouched.
//   - HandleArchiveKeyRotateCommit : promote staging → active (overwriting and
//     thereby wiping the old active private key), clear staging.
//   - HandleArchiveKeyRotateAbort  : discard staging.
//
// Between begin and commit, archive_unwrap_and_rewrap still unwraps with the
// OLD active key (it never consults the staging slot), so the caller can
// re-wrap every existing grant to the staged public key before committing.
//
// Private material is held only in memguard buffers during the save window and
// never crosses into a response — responses expose only public key + fingerprint.
//
// org_id (0.0.58) scopes the stage and the committed key to one org. The
// device-wide stage of an older Keeper is never overwritten or aborted by an
// org-scoped call, since it may belong to another org's rotation whose
// outcome is unknown; an org-scoped commit or rewrap still finds it when the
// org has no stage of its own, so a rotation begun before the upgrade can
// finish. An org-scoped commit never writes the device-wide active slot: the
// other orgs on this device may still have grants wrapped to it.

package handlers

import (
	"github.com/awnumar/memguard"

	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/secure"
)

// HandleArchiveKeyRotateBegin generates a new archive keypair into the org's
// staging slot without touching any active slot. Requires an active key for
// the org (rotation, not first-time enable). The org's own stage is wiped and
// replaced; no other stage is touched.
func HandleArchiveKeyRotateBegin(d Deps, req proto.ArchiveKeyRotateBeginRequest) proto.BaseResponse {
	d.Logger.Println("archive key rotate begin processing...")

	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}

	// Rotation requires an existing active key. First-time enable is
	// archive_key_generate — signal that with a validation error, not a silent
	// bootstrap.
	_, _, found, err := keychain.FindArchiveKey(d.Store, keychain.OrgArchiveActiveCandidates(req.OrgID))
	if err != nil {
		d.Logger.Printf("archive key rotate begin: read active key failed: %v", err)
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "read active archive key failed")
	}
	if !found {
		d.Logger.Println("archive key rotate begin: no active key to rotate")
		return errs.CodeResponse(errs.ErrCodeValidation, "no active archive key to rotate (use archive_key_generate for first-time enable)")
	}

	// Overwrite any abandoned stage of this org: reusing it would bind this
	// rotation to a fingerprint the caller never saw. Wipe both halves before
	// regenerating.
	staging := keychain.OrgArchiveStagingSlot(req.OrgID)
	_ = staging.DeletePrivate(d.Store)
	_ = staging.DeletePublic(d.Store)

	keyPair, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		d.Logger.Printf("archive key rotate begin: keygen failed: %v", err)
		return errs.CodeResponse(errs.ErrCodeInternal, "archive key keygen failed: "+err.Error())
	}

	// Protect the private key PEM in memguard, save to the staging slot, wipe.
	privKeyBuf := memguard.NewBufferFromBytes([]byte(keyPair.PrivateKey))
	secure.WipeString(&keyPair.PrivateKey)
	defer privKeyBuf.Destroy()

	if err := staging.SavePrivate(d.Store, string(privKeyBuf.Bytes())); err != nil {
		d.Logger.Printf("archive key rotate begin: save staging priv failed: %v", err)
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "save staging archive priv key failed: "+err.Error())
	}
	if err := staging.SavePublic(d.Store, keyPair.PublicKey); err != nil {
		d.Logger.Printf("archive key rotate begin: save staging pub failed: %v", err)
		// Partial failure — only priv staged. The next begin call wipes and
		// regenerates, so it never gets stuck.
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "save staging archive pub key failed: "+err.Error())
	}

	d.Logger.Printf("archive key rotate begin: new rsa keypair staged (scope=%s, active key untouched)", staging.Scope)
	return proto.BaseResponse{Success: true, Data: proto.ArchiveKeyRotateBeginResponseData{
		PublicKey:   keyPair.PublicKey,
		Fingerprint: fingerprintBase64Public(keyPair.PublicKey),
		Scope:       staging.Scope,
	}}
}

// HandleArchiveKeyRotateCommit promotes the org's staged keypair to the org's
// active slot. Saving over the active slot replaces (wipes) the key it held
// at rest. Requires a stage to be present, and when expected_fingerprint is
// set, a stage with that fingerprint.
func HandleArchiveKeyRotateCommit(d Deps, req proto.ArchiveKeyRotateCommitRequest) proto.BaseResponse {
	d.Logger.Println("archive key rotate commit processing...")

	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}

	staging, stagingPub, found, err := keychain.FindArchiveKey(d.Store, keychain.OrgArchiveStagingCandidates(req.OrgID))
	if err != nil {
		d.Logger.Printf("archive key rotate commit: read staging key failed: %v", err)
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "read staging archive key failed")
	}
	if !found {
		d.Logger.Println("archive key rotate commit: no staging key to commit")
		return errs.CodeResponse(errs.ErrCodeNotFound, "no staging archive key to commit (call archive_key_rotate_begin first)")
	}
	if req.ExpectedFingerprint != "" && fingerprintBase64Public(stagingPub) != req.ExpectedFingerprint {
		d.Logger.Printf("archive key rotate commit: staged key (scope=%s) is not the expected one", staging.Scope)
		return errs.CodeResponse(errs.ErrCodeValidation, "staged archive key does not match expected_fingerprint")
	}
	stagingPriv, err := staging.GetPrivate(d.Store)
	if err != nil || stagingPriv == "" {
		secure.WipeString(&stagingPriv)
		d.Logger.Println("archive key rotate commit: staging private key missing")
		return errs.CodeResponse(errs.ErrCodeNotFound, "staging archive private key not found")
	}

	// Move the staged private half through memguard while overwriting the active
	// slot; the old active private key is replaced (wiped at rest) by this Save.
	privKeyBuf := memguard.NewBufferFromBytes([]byte(stagingPriv))
	secure.WipeString(&stagingPriv)
	defer privKeyBuf.Destroy()

	active := keychain.OrgArchiveActiveSlot(req.OrgID)
	if err := active.SavePrivate(d.Store, string(privKeyBuf.Bytes())); err != nil {
		d.Logger.Printf("archive key rotate commit: save active priv failed: %v", err)
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "promote staging archive priv key failed: "+err.Error())
	}
	if err := active.SavePublic(d.Store, stagingPub); err != nil {
		d.Logger.Printf("archive key rotate commit: save active pub failed: %v", err)
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "promote staging archive pub key failed: "+err.Error())
	}

	// Clear the stage that was promoted (best-effort — the active slot is now
	// the source of truth).
	_ = staging.DeletePrivate(d.Store)
	_ = staging.DeletePublic(d.Store)

	d.Logger.Printf("archive key rotate commit: %s stage promoted to %s active slot", staging.Scope, active.Scope)
	return proto.BaseResponse{Success: true, Data: proto.ArchiveKeyRotateCommitResponseData{
		Fingerprint: fingerprintBase64Public(stagingPub),
		Scope:       active.Scope,
	}}
}

// HandleArchiveKeyRotateAbort discards the org's own stage. no-op success when
// it has none. An org-scoped abort leaves the device-wide stage alone: which
// org it belongs to is unknown.
func HandleArchiveKeyRotateAbort(d Deps, req proto.ArchiveKeyRotateAbortRequest) proto.BaseResponse {
	d.Logger.Println("archive key rotate abort processing...")

	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}

	staging := keychain.OrgArchiveStagingSlot(req.OrgID)
	stagedPriv, err := staging.GetPrivate(d.Store)
	hadStaging := err == nil && stagedPriv != ""
	secure.WipeString(&stagedPriv)

	_ = staging.DeletePrivate(d.Store)
	_ = staging.DeletePublic(d.Store)

	d.Logger.Printf("archive key rotate abort: staging cleared (scope=%s, had_staging=%v)", staging.Scope, hadStaging)
	return proto.BaseResponse{Success: true, Data: proto.ArchiveKeyRotateAbortResponseData{
		Aborted: hadStaging,
	}}
}
