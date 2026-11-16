// archive_quorum_session.go — recovery-session keypair lifecycle.
//
// Part of the org archive-key admin quorum (Shamir N-of-M break-glass) flow;
// see archive_quorum_combine.go for the flow overview. The coordinator opens an
// ephemeral session keypair whose public key admins re-wrap their shares to
// (HandleArchiveShareRewrap), and whose private key reconstructs the archive
// key (HandleArchiveQuorumCombineAndRewrap). This file owns that keypair's
// begin/expiry/end lifecycle; archive_session_slot.go owns the slot record
// and its expiry rules.
//
// Key-material discipline: the session private key is held in a memguard buffer
// and the plaintext keypair string is wiped (secure.WipeString) once persisted;
// it never appears in a response.

package handlers

import (
	"errors"
	"time"

	"github.com/awnumar/memguard"

	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/secure"
)

// HandleArchiveSessionBegin generates the coordinator's ephemeral
// recovery-session keypair and returns its public key and the slot's expiry
// (begin + archiveSessionMaxTTL). Overwrites any prior session key (a new
// session supersedes an abandoned one).
func HandleArchiveSessionBegin(d Deps, req proto.ArchiveSessionBeginRequest) proto.BaseResponse {
	d.Logger.Println("archive session begin processing...")

	keyPair, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeInternal, "archive session keygen failed: "+err.Error())
	}

	privBuf := memguard.NewBufferFromBytes([]byte(keyPair.PrivateKey))
	secure.WipeString(&keyPair.PrivateKey)
	defer privBuf.Destroy()

	expiresAt := d.Now().Add(archiveSessionMaxTTL)
	record := encodeArchiveSessionSlot(expiresAt, privBuf.Bytes())
	defer record.Destroy()

	if err := keychain.SaveArchiveSessionPrivateKey(d.Store, string(record.Bytes())); err != nil {
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "save archive session priv key failed: "+err.Error())
	}
	if err := keychain.SaveArchiveSessionPublicKey(d.Store, keyPair.PublicKey); err != nil {
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "save archive session pub key failed: "+err.Error())
	}

	d.Logger.Println("archive session begin: ephemeral keypair created")
	return proto.BaseResponse{Success: true, Data: proto.ArchiveSessionBeginResponseData{
		SessionPublicKey: keyPair.PublicKey,
		Fingerprint:      fingerprintBase64Public(keyPair.PublicKey),
		ExpiresAt:        formatArchiveSessionExpiry(expiresAt),
	}}
}

// HandleArchiveSessionSetExpiry applies the server's session expires_at to
// the slot of the session whose public key has req.Fingerprint. The slot's
// expiry only moves earlier: a later or forged value leaves the Keeper-side
// bound in place. Reading the slot is a use, so an expired slot is deleted
// and one without expiry is refused and kept.
func HandleArchiveSessionSetExpiry(d Deps, req proto.ArchiveSessionSetExpiryRequest) proto.BaseResponse {
	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}
	serverExpiry, _ := time.Parse(time.RFC3339, req.ExpiresAt) // validated

	pemBuf, current, err := openArchiveSessionSlot(d)
	if err != nil {
		return archiveSessionSlotResponse(err)
	}
	defer pemBuf.Destroy()
	if !archiveSessionFingerprintMatches(d, req.Fingerprint) {
		return errs.CodeResponse(errs.ErrCodeNotFound, "no archive session with this fingerprint")
	}

	expiresAt := current
	if serverExpiry.Before(expiresAt) {
		expiresAt = serverExpiry
	}
	if !d.Now().Before(expiresAt) {
		deleteArchiveSessionSlot(d)
		return archiveSessionSlotResponse(errArchiveSessionExpired)
	}
	if expiresAt.Before(current) {
		record := encodeArchiveSessionSlot(expiresAt, pemBuf.Bytes())
		defer record.Destroy()
		if err := keychain.SaveArchiveSessionPrivateKey(d.Store, string(record.Bytes())); err != nil {
			return errs.CodeResponse(errs.ErrCodeStorageFailure, "save archive session expiry failed")
		}
	}
	return proto.BaseResponse{Success: true, Data: proto.ArchiveSessionSetExpiryResponseData{
		ExpiresAt: formatArchiveSessionExpiry(expiresAt),
	}}
}

// HandleArchiveSessionEnd destroys the recovery-session keypair. Idempotent —
// ended=false when no session was present. With req.Fingerprint it ends only
// the session whose public key has that fingerprint, so a late end for an
// earlier session cannot remove a newer one.
//
// A slot without a Keeper-written expiry (written before lv100 F1) is kept
// and reported as slot_without_expiry_kept: lv90 leaves its deletion to the
// user's confirmed discard. Uses already refuse it.
func HandleArchiveSessionEnd(d Deps, req proto.ArchiveSessionEndRequest) proto.BaseResponse {
	d.Logger.Println("archive session end processing...")
	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}

	existing, err := keychain.GetArchiveSessionPrivateKey(d.Store)
	present := err == nil && existing != ""
	_, _, carriesExpiry := decodeArchiveSessionSlot(existing)
	secure.WipeString(&existing)
	if err != nil && !errors.Is(err, keychain.ErrSecretNotFound) {
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "read archive session slot failed")
	}

	if present && req.Fingerprint != "" && !archiveSessionFingerprintMatches(d, req.Fingerprint) {
		return proto.BaseResponse{Success: true, Data: proto.ArchiveSessionEndResponseData{Ended: false}}
	}
	if present && !carriesExpiry {
		return proto.BaseResponse{Success: true, Data: proto.ArchiveSessionEndResponseData{SlotWithoutExpiryKept: true}}
	}

	deleteArchiveSessionSlot(d)
	return proto.BaseResponse{Success: true, Data: proto.ArchiveSessionEndResponseData{Ended: present}}
}

// SweepExpiredArchiveSession runs once when the Keeper process starts,
// before it serves any action, so a session key left by a crash or a lost
// App is destroyed as soon as its expiry has passed even if nothing ever
// uses or ends it. It deletes only a slot carrying an expiry this Keeper
// wrote; a slot without one is left for the confirmed discard.
func SweepExpiredArchiveSession(d Deps) {
	value, err := keychain.GetArchiveSessionPrivateKey(d.Store)
	if err != nil || value == "" {
		return
	}
	expiresAt, _, ok := decodeArchiveSessionSlot(value)
	secure.WipeString(&value)
	if ok && !d.Now().Before(expiresAt) {
		deleteArchiveSessionSlot(d)
		d.Logger.Println("archive session: expired session key destroyed at startup")
	}
}

func formatArchiveSessionExpiry(t time.Time) string {
	return t.UTC().Format(time.RFC3339)
}
