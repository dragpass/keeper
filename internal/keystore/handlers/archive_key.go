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

// HandleArchiveKeyStatus reports active archive key presence + public key +
// fingerprint. Absence is normal (org has not enabled archive keys yet), so it
// returns 200 with has_active=false.
func HandleArchiveKeyStatus(d Deps, req proto.ArchiveKeyStatusRequest) proto.BaseResponse {
	d.Logger.Println("archive key status processing...")

	pub, err := keychain.GetArchivePublicKey(d.Store)
	if err != nil || pub == "" {
		return proto.BaseResponse{Success: true, Data: proto.ArchiveKeyStatusResponseData{
			HasActive: false,
		}}
	}
	return proto.BaseResponse{Success: true, Data: proto.ArchiveKeyStatusResponseData{
		HasActive:   true,
		PublicKey:   pub,
		Fingerprint: fingerprintBase64Public(pub),
	}}
}

// archiveUnwrapWithSlot fetches a private key with getKey, parses it, and
// RSA-OAEP-decrypts encrypted. Helper for HandleArchiveUnwrapAndRewrap's
// org-slot → account-slot fallback; each error keeps its source so the caller
// can decide whether falling back makes sense.
func archiveUnwrapWithSlot(
	d Deps,
	getKey func(keychain.SecretStore) (*memguard.LockedBuffer, error),
	encrypted []byte,
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
	return crypto.DecryptData(privKey, encrypted)
}

// HandleArchiveUnwrapAndRewrap is the break-glass re-grant composite. It
// unwraps an OLD Group DEK that was wrapped to the org archive public key
// (org_owner_archive grant) with the archive private key, then re-wraps it to
// a target member's public key. The raw Group DEK lives only briefly in Keeper
// memory and is never in the response — same raw-free pattern as
// HandleDEKRewrapForMember. The archive private key never leaves its slot.
//
// Unwrap tries the ORG archive slot first, then falls back to the ACCOUNT
// archive slot: after an ownership handoff, grants are re-wrapped to the new
// owner's account directory key, which lives in the account slot, while the
// org slot may hold an unrelated key (or none). Both slots failing surfaces
// the org-slot error (not_found when neither slot has a key).
func HandleArchiveUnwrapAndRewrap(d Deps, req proto.ArchiveUnwrapAndRewrapRequest) proto.BaseResponse {
	d.Logger.Println("archive unwrap and rewrap request processing...")

	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}

	recipientPubKey, err := crypto.ParsePublicKey(req.RecipientPublicKey)
	if err != nil {
		d.Logger.Printf("archive unwrap and rewrap error: failed to parse recipient public key: %v", err)
		return errs.CodeResponse(errs.ErrCodeValidation, "failed to parse recipient public key: "+err.Error())
	}

	encrypted, err := base64.StdEncoding.DecodeString(req.WrappedForArchiveB64)
	if err != nil {
		d.Logger.Printf("archive unwrap and rewrap error: failed to decode wrapped_for_archive_b64: %v", err)
		return errs.CodeResponse(errs.ErrCodeValidation, "failed to decode wrapped_for_archive_b64: "+err.Error())
	}

	groupDEK, orgErr := archiveUnwrapWithSlot(d, GetArchivePrivateKeySecure, encrypted)
	if orgErr != nil {
		var accErr error
		groupDEK, accErr = archiveUnwrapWithSlot(d, GetAccountArchivePrivateKeySecure, encrypted)
		if accErr != nil {
			d.Logger.Printf("archive unwrap and rewrap error: org slot: %v; account slot: %v", orgErr, accErr)
			// Neither slot worked. Prefer the org-slot error for the coarse
			// code: missing org slot stays not_found (re-bootstrap signal);
			// an org-slot decrypt failure is crypto_failure.
			if resp := errs.Response(orgErr); resp.ErrorCode == string(errs.ErrCodeNotFound) {
				return resp
			}
			return errs.CodeResponse(errs.ErrCodeCryptoFailure, "RSA-OAEP decrypt failed: "+orgErr.Error())
		}
		d.Logger.Println("archive unwrap and rewrap: org slot failed, account archive slot succeeded (handoff-received grant)")
	}
	defer secure.Zeroize(groupDEK)

	if len(groupDEK) != 32 {
		return errs.CodeResponse(errs.ErrCodeCryptoFailure, errors.New("unexpected group dek length (want 32)").Error())
	}

	newEncrypted, err := crypto.EncryptData(recipientPubKey, groupDEK)
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
