// archive_quorum_session.go — recovery-session keypair lifecycle.
//
// Part of the org archive-key admin quorum (Shamir N-of-M break-glass) flow;
// see archive_quorum_combine.go for the flow overview. The coordinator opens an
// ephemeral session keypair whose public key admins re-wrap their shares to
// (HandleArchiveShareRewrap), and whose private key reconstructs the archive
// key (HandleArchiveQuorumCombineAndRewrap). This file owns only that keypair's
// begin/end lifecycle.
//
// Key-material discipline: the session private key is held in a memguard buffer
// and the plaintext keypair string is wiped (secure.WipeString) once persisted;
// it never appears in a response.

package handlers

import (
	"github.com/awnumar/memguard"

	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/secure"
)

// HandleArchiveSessionBegin generates the coordinator's ephemeral
// recovery-session keypair and returns its public key. Overwrites any prior
// session key (a new session supersedes an abandoned one).
func HandleArchiveSessionBegin(d Deps, req proto.ArchiveSessionBeginRequest) proto.BaseResponse {
	d.Logger.Println("archive session begin processing...")

	keyPair, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeInternal, "archive session keygen failed: "+err.Error())
	}

	privBuf := memguard.NewBufferFromBytes([]byte(keyPair.PrivateKey))
	secure.WipeString(&keyPair.PrivateKey)
	defer privBuf.Destroy()

	if err := keychain.SaveArchiveSessionPrivateKey(d.Store, string(privBuf.Bytes())); err != nil {
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "save archive session priv key failed: "+err.Error())
	}
	if err := keychain.SaveArchiveSessionPublicKey(d.Store, keyPair.PublicKey); err != nil {
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "save archive session pub key failed: "+err.Error())
	}

	d.Logger.Println("archive session begin: ephemeral keypair created")
	return proto.BaseResponse{Success: true, Data: proto.ArchiveSessionBeginResponseData{
		SessionPublicKey: keyPair.PublicKey,
		Fingerprint:      fingerprintBase64Public(keyPair.PublicKey),
	}}
}

// HandleArchiveSessionEnd destroys the recovery-session keypair. Idempotent —
// ended=false when no session was present.
func HandleArchiveSessionEnd(d Deps, req proto.ArchiveSessionEndRequest) proto.BaseResponse {
	d.Logger.Println("archive session end processing...")

	existing, _ := keychain.GetArchiveSessionPrivateKey(d.Store)
	ended := existing != ""

	_ = keychain.DeleteArchiveSessionPrivateKey(d.Store)
	_ = keychain.DeleteArchiveSessionPublicKey(d.Store)

	return proto.BaseResponse{Success: true, Data: proto.ArchiveSessionEndResponseData{Ended: ended}}
}
