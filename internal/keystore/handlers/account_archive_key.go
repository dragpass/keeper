// account_archive_key.go — per-account Archive / Recovery receiving keypair
// handlers.
//
// Mirrors the org archive handlers (archive_key.go) against the dedicated
// ACCOUNT slot. The account key is published to the server account directory
// (account_archive_keys) and receives ownership-handoff grants and archive
// quorum Shamir shares. It is deliberately a separate slot from the org
// archive keypair: archive_key_split deletes the org private key when quorum
// is enabled, and the account key must survive that wipe.

package handlers

import (
	"github.com/awnumar/memguard"

	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/secure"
)

// HandleAccountArchiveKeyGenerate generates an RSA account archive keypair if
// none exists. Idempotent: when a key is already present, only its meta is
// returned.
func HandleAccountArchiveKeyGenerate(d Deps, req proto.AccountArchiveKeyGenerateRequest) proto.BaseResponse {
	d.Logger.Println("account archive key generate processing...")

	if existing, err := keychain.GetAccountArchivePublicKey(d.Store); err == nil && existing != "" {
		d.Logger.Println("account archive key generate: active key already present, returning meta")
		return proto.BaseResponse{Success: true, Data: proto.AccountArchiveKeyGenerateResponseData{
			PublicKey:   existing,
			Fingerprint: fingerprintBase64Public(existing),
		}}
	}

	keyPair, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		d.Logger.Printf("account archive key generate: keygen failed: %v", err)
		return errs.CodeResponse(errs.ErrCodeInternal, "account archive key keygen failed: "+err.Error())
	}

	privKeyBuf := memguard.NewBufferFromBytes([]byte(keyPair.PrivateKey))
	secure.WipeString(&keyPair.PrivateKey)
	defer privKeyBuf.Destroy()

	if err := keychain.SaveAccountArchivePrivateKey(d.Store, string(privKeyBuf.Bytes())); err != nil {
		d.Logger.Printf("account archive key generate: save priv failed: %v", err)
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "save account archive priv key failed: "+err.Error())
	}
	if err := keychain.SaveAccountArchivePublicKey(d.Store, keyPair.PublicKey); err != nil {
		d.Logger.Printf("account archive key generate: save pub failed: %v", err)
		// Partial failure — only priv saved. The next generate sees the pub
		// slot as empty and regenerates, overwriting the priv slot.
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "save account archive pub key failed: "+err.Error())
	}

	d.Logger.Println("account archive key generate: new rsa keypair saved")
	return proto.BaseResponse{Success: true, Data: proto.AccountArchiveKeyGenerateResponseData{
		PublicKey:   keyPair.PublicKey,
		Fingerprint: fingerprintBase64Public(keyPair.PublicKey),
	}}
}

// HandleAccountArchiveKeyStatus reports account archive key presence + public
// key + fingerprint. Absence is normal (not yet published to the directory).
func HandleAccountArchiveKeyStatus(d Deps, req proto.AccountArchiveKeyStatusRequest) proto.BaseResponse {
	d.Logger.Println("account archive key status processing...")

	pub, err := keychain.GetAccountArchivePublicKey(d.Store)
	if err != nil || pub == "" {
		return proto.BaseResponse{Success: true, Data: proto.AccountArchiveKeyStatusResponseData{
			HasActive: false,
		}}
	}
	return proto.BaseResponse{Success: true, Data: proto.AccountArchiveKeyStatusResponseData{
		HasActive:   true,
		PublicKey:   pub,
		Fingerprint: fingerprintBase64Public(pub),
	}}
}
