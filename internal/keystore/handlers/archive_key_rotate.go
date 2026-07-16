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

package handlers

import (
	"github.com/awnumar/memguard"

	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/secure"
)

// HandleArchiveKeyRotateBegin generates a new archive keypair into the staging
// slot without touching the active slot. Requires an active key (rotation, not
// first-time enable). Any existing staging is wiped and replaced.
func HandleArchiveKeyRotateBegin(d Deps, req proto.ArchiveKeyRotateBeginRequest) proto.BaseResponse {
	d.Logger.Println("archive key rotate begin processing...")

	// Rotation requires an existing active key. First-time enable is
	// archive_key_generate — signal that with a validation error, not a silent
	// bootstrap.
	if active, err := keychain.GetArchivePublicKey(d.Store); err != nil || active == "" {
		d.Logger.Println("archive key rotate begin: no active key to rotate")
		return errs.CodeResponse(errs.ErrCodeValidation, "no active archive key to rotate (use archive_key_generate for first-time enable)")
	}

	// Overwrite any abandoned staging: reusing it would bind this rotation to a
	// fingerprint the caller never saw. Wipe both halves before regenerating.
	_ = keychain.DeleteArchiveStagingPrivateKey(d.Store)
	_ = keychain.DeleteArchiveStagingPublicKey(d.Store)

	keyPair, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		d.Logger.Printf("archive key rotate begin: keygen failed: %v", err)
		return errs.CodeResponse(errs.ErrCodeInternal, "archive key keygen failed: "+err.Error())
	}

	// Protect the private key PEM in memguard, save to the staging slot, wipe.
	privKeyBuf := memguard.NewBufferFromBytes([]byte(keyPair.PrivateKey))
	secure.WipeString(&keyPair.PrivateKey)
	defer privKeyBuf.Destroy()

	if err := keychain.SaveArchiveStagingPrivateKey(d.Store, string(privKeyBuf.Bytes())); err != nil {
		d.Logger.Printf("archive key rotate begin: save staging priv failed: %v", err)
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "save staging archive priv key failed: "+err.Error())
	}
	if err := keychain.SaveArchiveStagingPublicKey(d.Store, keyPair.PublicKey); err != nil {
		d.Logger.Printf("archive key rotate begin: save staging pub failed: %v", err)
		// Partial failure — only priv staged. The next begin call wipes and
		// regenerates, so it never gets stuck.
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "save staging archive pub key failed: "+err.Error())
	}

	d.Logger.Println("archive key rotate begin: new rsa keypair staged (active key untouched)")
	return proto.BaseResponse{Success: true, Data: proto.ArchiveKeyRotateBeginResponseData{
		PublicKey:   keyPair.PublicKey,
		Fingerprint: fingerprintBase64Public(keyPair.PublicKey),
	}}
}

// HandleArchiveKeyRotateCommit promotes the staged keypair to the active slot.
// Saving the staged private key over the active slot replaces (wipes) the old
// active private key at rest. Requires a staging key to be present.
func HandleArchiveKeyRotateCommit(d Deps, req proto.ArchiveKeyRotateCommitRequest) proto.BaseResponse {
	d.Logger.Println("archive key rotate commit processing...")

	stagingPriv, err := keychain.GetArchiveStagingPrivateKey(d.Store)
	if err != nil || stagingPriv == "" {
		d.Logger.Println("archive key rotate commit: no staging key to commit")
		return errs.CodeResponse(errs.ErrCodeNotFound, "no staging archive key to commit (call archive_key_rotate_begin first)")
	}
	stagingPub, pubErr := keychain.GetArchiveStagingPublicKey(d.Store)
	if pubErr != nil || stagingPub == "" {
		secure.WipeString(&stagingPriv)
		d.Logger.Println("archive key rotate commit: staging public key missing")
		return errs.CodeResponse(errs.ErrCodeNotFound, "staging archive public key not found")
	}

	// Move the staged private half through memguard while overwriting the active
	// slot; the old active private key is replaced (wiped at rest) by this Save.
	privKeyBuf := memguard.NewBufferFromBytes([]byte(stagingPriv))
	secure.WipeString(&stagingPriv)
	defer privKeyBuf.Destroy()

	if err := keychain.SaveArchivePrivateKey(d.Store, string(privKeyBuf.Bytes())); err != nil {
		d.Logger.Printf("archive key rotate commit: save active priv failed: %v", err)
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "promote staging archive priv key failed: "+err.Error())
	}
	if err := keychain.SaveArchivePublicKey(d.Store, stagingPub); err != nil {
		d.Logger.Printf("archive key rotate commit: save active pub failed: %v", err)
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "promote staging archive pub key failed: "+err.Error())
	}

	// Clear the staging slot (best-effort — the active slot is now the source of
	// truth).
	_ = keychain.DeleteArchiveStagingPrivateKey(d.Store)
	_ = keychain.DeleteArchiveStagingPublicKey(d.Store)

	d.Logger.Println("archive key rotate commit: staging promoted to active (old active key wiped)")
	return proto.BaseResponse{Success: true, Data: proto.ArchiveKeyRotateCommitResponseData{
		Fingerprint: fingerprintBase64Public(stagingPub),
	}}
}

// HandleArchiveKeyRotateAbort discards the staging slot. no-op success when no
// staging is present.
func HandleArchiveKeyRotateAbort(d Deps, req proto.ArchiveKeyRotateAbortRequest) proto.BaseResponse {
	d.Logger.Println("archive key rotate abort processing...")

	staging, err := keychain.GetArchiveStagingPrivateKey(d.Store)
	hadStaging := err == nil && staging != ""
	secure.WipeString(&staging)

	_ = keychain.DeleteArchiveStagingPrivateKey(d.Store)
	_ = keychain.DeleteArchiveStagingPublicKey(d.Store)

	d.Logger.Printf("archive key rotate abort: staging cleared (had_staging=%v)", hadStaging)
	return proto.BaseResponse{Success: true, Data: proto.ArchiveKeyRotateAbortResponseData{
		Aborted: hadStaging,
	}}
}
