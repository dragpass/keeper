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
// open session for each of several organizations.
//
// The device-wide slot (config.LegacyOrgArchiveSessionPrivateKey) that Keepers
// before lv90 used names no organization and may hold the key of an
// in-flight recovery session. No action reads it as a session key or moves
// it. begin refuses with archive_session_legacy_slot_present while it exists;
// end leaves it alone; only archive_session_legacy_discard, which the App
// calls after the user confirms, deletes it.
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

	// The device-wide slot of a Keeper before lv90 may hold the key of an
	// in-flight recovery session of an organization this Keeper cannot name.
	// It is never deleted, moved or used here; the App asks the user, then
	// calls archive_session_legacy_discard.
	if present, err := keychain.LegacyArchiveSessionPresent(d.Store); err != nil {
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "read device-wide archive session slot failed")
	} else if present {
		return errs.CodeResponse(errs.ErrCodeArchiveSessionLegacySlotPresent, "a device-wide archive recovery session key from an earlier Keeper is present")
	}

	keyPair, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeInternal, "archive session keygen failed: "+err.Error())
	}

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

	existing, _ := keychain.GetArchiveSessionPrivateKey(d.Store, req.OrgID)
	ended := existing != ""
	secure.WipeString(&existing)

	_ = keychain.DeleteArchiveSessionPrivateKey(d.Store, req.OrgID)
	_ = keychain.DeleteArchiveSessionPublicKey(d.Store, req.OrgID)

	return proto.BaseResponse{Success: true, Data: proto.ArchiveSessionEndResponseData{Ended: ended}}
}

// HandleArchiveSessionLegacyDiscard deletes both halves of the device-wide
// session slot a Keeper before lv90 used. The App calls it only after the
// user confirmed: if that key belongs to a recovery session still open on
// the server, the approvals already given to it can no longer be combined,
// and the owner cancels that session and opens a new one. Organization
// session slots and every other slot are untouched. Idempotent:
// discarded=false when nothing was there.
func HandleArchiveSessionLegacyDiscard(d Deps, req proto.ArchiveSessionLegacyDiscardRequest) proto.BaseResponse {
	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}
	present, err := keychain.LegacyArchiveSessionPresent(d.Store)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "read device-wide archive session slot failed")
	}
	if err := keychain.DeleteLegacyArchiveSessionKeys(d.Store); err != nil {
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "delete device-wide archive session slot failed")
	}
	if present {
		d.Logger.Println("archive session legacy discard: device-wide session slot deleted on confirmed request")
	}
	return proto.BaseResponse{Success: true, Data: proto.ArchiveSessionLegacyDiscardResponseData{Discarded: present}}
}
