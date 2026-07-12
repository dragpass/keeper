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
