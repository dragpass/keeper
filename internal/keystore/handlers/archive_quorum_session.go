// archive_quorum_session.go — recovery-session keypair lifecycle.
//
// Part of the org archive-key admin quorum (Shamir N-of-M break-glass) flow;
// see archive_quorum_combine.go for the flow overview. The coordinator opens an
// ephemeral session keypair whose public key admins re-wrap their shares to
// (HandleArchiveShareRewrap), and whose private key reconstructs the archive
// key (HandleArchiveQuorumCombineAndRewrap). This file owns only that keypair's
// begin/end lifecycle.
//
// The keypair lives in the organization's own slot
// (config.OrgArchiveSessionPrivateKeyPrefix + org_id): one device can hold an
// open session for each of several organizations. The device-wide slot of
// Keepers before lv90 names no organization; begin and end remove a leftover
// entry and nothing reads it, so a session opened under it fails closed.
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
// recovery-session keypair for req.OrgID and returns its public key.
// Overwrites any prior session key of that organization (a new session
// supersedes an abandoned one); other organizations' sessions are untouched.
func HandleArchiveSessionBegin(d Deps, req proto.ArchiveSessionBeginRequest) proto.BaseResponse {
	d.Logger.Println("archive session begin processing...")
	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}

	keyPair, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeInternal, "archive session keygen failed: "+err.Error())
	}

	removeLegacyArchiveSession(d)

	privBuf := memguard.NewBufferFromBytes([]byte(keyPair.PrivateKey))
	secure.WipeString(&keyPair.PrivateKey)
	defer privBuf.Destroy()

	if err := keychain.SaveArchiveSessionPrivateKey(d.Store, req.OrgID, string(privBuf.Bytes())); err != nil {
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "save archive session priv key failed: "+err.Error())
	}
	if err := keychain.SaveArchiveSessionPublicKey(d.Store, req.OrgID, keyPair.PublicKey); err != nil {
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "save archive session pub key failed: "+err.Error())
	}

	d.Logger.Println("archive session begin: ephemeral keypair created")
	return proto.BaseResponse{Success: true, Data: proto.ArchiveSessionBeginResponseData{
		SessionPublicKey: keyPair.PublicKey,
		Fingerprint:      fingerprintBase64Public(keyPair.PublicKey),
	}}
}

// HandleArchiveSessionEnd destroys req.OrgID's recovery-session keypair.
// Idempotent — ended=false when that organization had no session.
func HandleArchiveSessionEnd(d Deps, req proto.ArchiveSessionEndRequest) proto.BaseResponse {
	d.Logger.Println("archive session end processing...")
	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}

	removeLegacyArchiveSession(d)
	existing, _ := keychain.GetArchiveSessionPrivateKey(d.Store, req.OrgID)
	ended := existing != ""
	secure.WipeString(&existing)

	_ = keychain.DeleteArchiveSessionPrivateKey(d.Store, req.OrgID)
	_ = keychain.DeleteArchiveSessionPublicKey(d.Store, req.OrgID)

	return proto.BaseResponse{Success: true, Data: proto.ArchiveSessionEndResponseData{Ended: ended}}
}

// removeLegacyArchiveSession drops a device-wide session entry left by a Keeper
// before lv90. A failure is logged and does not block the call: the entry is
// never read, so leaving it costs nothing but the stale key at rest.
func removeLegacyArchiveSession(d Deps) {
	if err := keychain.DeleteLegacyArchiveSessionKeys(d.Store); err != nil {
		d.Logger.Println("archive session: removing the device-wide session slot failed")
	}
}
