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
// The keypair lives in the organization's own slot
// (config.OrgArchiveSessionPrivateKeyPrefix + org_id): one device can hold an
// open session for each of several organizations, and every action names the
// organization whose slot it reads, changes or deletes.
//
// The device-wide slot (config.LegacyOrgArchiveSessionPrivateKey) that Keepers
// before lv90 used names no organization and may hold the key of an
// in-flight recovery session. No action reads it as a session key or moves
// it, whatever its content (with or without an expiry header). begin refuses
// with archive_session_legacy_slot_present while it exists; end, set_expiry,
// combine and the startup sweep leave it alone; only
// archive_session_legacy_discard, which the App calls after the user
// confirms, deletes it.
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

var errArchiveSessionLegacySlotPresent = errors.New("device-wide archive session slot present")

// HandleArchiveSessionBegin generates the coordinator's ephemeral
// recovery-session keypair for req.OrgID and returns its public key and the
// slot's expiry (begin + archiveSessionMaxTTL). It replaces a session key of
// that organization Keeper trusts; a slot whose expiry or record it cannot
// trust is refused with archive_session_active and kept. Other
// organizations' sessions are untouched.
func HandleArchiveSessionBegin(d Deps, req proto.ArchiveSessionBeginRequest) proto.BaseResponse {
	d.Logger.Println("archive session begin processing...")
	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}

	keyPair, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeInternal, "archive session keygen failed: "+err.Error())
	}

	privBuf := memguard.NewBufferFromBytes([]byte(keyPair.PrivateKey))
	secure.WipeString(&keyPair.PrivateKey)
	defer privBuf.Destroy()

	now := d.Now()
	rec := archiveSessionRecord{
		expiresAt:   now.Add(archiveSessionMaxTTL),
		begunAt:     now,
		fingerprint: fingerprintBase64Public(keyPair.PublicKey),
	}
	record := encodeArchiveSessionSlot(rec, privBuf.Bytes())
	defer record.Destroy()

	// The device-wide check, the slot judgement and every write run under
	// the lock, so a startup sweep, an end or a discard in another process
	// never acts on a read taken before this write.
	var refusal proto.BaseResponse
	err = withArchiveSessionSlotLock(d, func() error {
		// The device-wide slot of a Keeper before lv90 may hold the key of an
		// in-flight recovery session of an organization this Keeper cannot
		// name. It is never deleted, moved or used here; the App asks the
		// user, then calls archive_session_legacy_discard.
		present, err := keychain.LegacyArchiveSessionPresent(d.Store)
		if err != nil {
			return errors.New("read device-wide archive session slot failed")
		}
		if present {
			return errArchiveSessionLegacySlotPresent
		}
		slot, err := inspectArchiveSessionSlotLocked(d, req.OrgID, nil)
		if err != nil {
			return errors.New("read archive session slot failed")
		}
		if !slot.state.trusted() && slot.state != archiveSessionSlotAbsent {
			refusal = archiveSessionActiveResponse(slot)
			return nil
		}
		return writeArchiveSessionSlotLocked(d, req.OrgID, keyPair.PublicKey, record.Bytes())
	})
	if errors.Is(err, errArchiveSessionLegacySlotPresent) {
		return errs.CodeResponse(errs.ErrCodeArchiveSessionLegacySlotPresent, "a device-wide archive recovery session key from an earlier Keeper is present")
	}
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeStorageFailure, err.Error())
	}
	if refusal.ErrorCode != "" {
		return refusal
	}

	d.Logger.Println("archive session begin: ephemeral keypair created")
	return proto.BaseResponse{Success: true, Data: proto.ArchiveSessionBeginResponseData{
		SessionPublicKey: keyPair.PublicKey,
		Fingerprint:      rec.fingerprint,
		ExpiresAt:        formatArchiveSessionExpiry(rec.expiresAt),
	}}
}

// writeArchiveSessionSlotLocked stores a new session keypair in orgID's slot.
// The index entry comes first, so a slot is never left where the startup
// sweep cannot find it. A private record already there goes before the new
// public half is written, and the new private record comes last: an
// interruption at any point leaves either the old trusted slot, no private
// record (an absent slot), or the complete new one, never halves of two
// keys. The caller holds the lock and has judged the slot replaceable.
func writeArchiveSessionSlotLocked(d Deps, orgID, publicKey string, record []byte) error {
	if err := keychain.AddArchiveSessionOrg(d.Store, orgID); err != nil {
		return errors.New("save archive session index failed: " + err.Error())
	}
	if err := keychain.DeleteArchiveSessionPrivateKey(d.Store, orgID); err != nil && !errors.Is(err, keychain.ErrSecretNotFound) {
		return errors.New("delete replaced archive session priv key failed: " + err.Error())
	}
	if err := keychain.SaveArchiveSessionPublicKey(d.Store, orgID, publicKey); err != nil {
		return errors.New("save archive session pub key failed: " + err.Error())
	}
	if err := keychain.SaveArchiveSessionPrivateKey(d.Store, orgID, string(record)); err != nil {
		return errors.New("save archive session priv key failed: " + err.Error())
	}
	return nil
}

// archiveSessionActiveResponse refuses a begin over slot. A fingerprint is a
// public key fingerprint; an expiry is reported only for a live slot.
func archiveSessionActiveResponse(slot archiveSessionSlot) proto.BaseResponse {
	data := proto.ArchiveSessionActiveData{Fingerprint: slot.fingerprint}
	switch slot.state {
	case archiveSessionSlotLive:
		data.State = proto.ArchiveSessionStateLive
		data.ExpiresAt = formatArchiveSessionExpiry(slot.record.expiresAt)
	case archiveSessionSlotExpiryUnknown:
		data.State = proto.ArchiveSessionStateExpiryUnknown
	default:
		data.State = proto.ArchiveSessionStateUnowned
	}
	return proto.BaseResponse{
		Error:     "the organization's archive session slot holds a key that is not replaced",
		ErrorCode: string(errs.ErrCodeArchiveSessionActive),
		Data:      data,
	}
}

// HandleArchiveSessionSetExpiry applies the server's session expires_at to
// req.OrgID's slot when it holds the session whose public key has
// req.Fingerprint. The slot's expiry only moves earlier: a later or forged
// value leaves the Keeper-side bound in place. Reading the slot is a use, so
// an expired slot is deleted and an untrusted one is refused and kept.
func HandleArchiveSessionSetExpiry(d Deps, req proto.ArchiveSessionSetExpiryRequest) proto.BaseResponse {
	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}
	serverExpiry, _ := time.Parse(time.RFC3339, req.ExpiresAt) // validated

	var expiresAt time.Time
	var refusal proto.BaseResponse
	err := withArchiveSessionSlotLock(d, func() error {
		var pem string
		slot, err := inspectArchiveSessionSlotLocked(d, req.OrgID, func(p string) { pem = p })
		defer secure.WipeString(&pem)
		if err != nil {
			return err
		}
		return useArchiveSessionSlotLocked(d, req.OrgID, slot, func() {
			if slot.fingerprint != req.Fingerprint {
				refusal = errs.CodeResponse(errs.ErrCodeNotFound, "no archive session with this fingerprint")
				return
			}
			refusal = shortenArchiveSessionSlotLocked(d, req.OrgID, slot, pem, serverExpiry, &expiresAt)
		})
	})
	if err != nil {
		return archiveSessionSlotResponse(err)
	}
	if refusal.ErrorCode != "" {
		return refusal
	}
	return proto.BaseResponse{Success: true, Data: proto.ArchiveSessionSetExpiryResponseData{
		ExpiresAt: formatArchiveSessionExpiry(expiresAt),
	}}
}

// shortenArchiveSessionSlotLocked moves a live slot's expiry to serverExpiry
// when that is earlier, deleting the slot when the result has passed. It sets
// *effective to the slot's expiry afterwards. The caller holds the lock.
func shortenArchiveSessionSlotLocked(d Deps, orgID string, slot archiveSessionSlot, pem string, serverExpiry time.Time, effective *time.Time) proto.BaseResponse {
	rec := slot.record
	if serverExpiry.Before(rec.expiresAt) {
		rec.expiresAt = serverExpiry
	}
	if !d.Now().Before(rec.expiresAt) {
		deleteArchiveSessionSlot(d, orgID)
		return archiveSessionSlotResponse(errArchiveSessionExpired)
	}
	*effective = rec.expiresAt
	if !rec.expiresAt.Before(slot.record.expiresAt) {
		return proto.BaseResponse{}
	}
	record := encodeArchiveSessionSlot(rec, []byte(pem))
	defer record.Destroy()
	if err := keychain.SaveArchiveSessionPrivateKey(d.Store, orgID, string(record.Bytes())); err != nil {
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "save archive session expiry failed")
	}
	// The stored value has whole seconds; report what is stored.
	*effective = time.Unix(rec.expiresAt.Unix(), 0)
	return proto.BaseResponse{}
}

// HandleArchiveSessionEnd destroys req.OrgID's recovery-session keypair.
// Idempotent — ended=false when that organization had no session. With
// req.Fingerprint it ends only the session whose public key has that
// fingerprint, so a late end for an earlier session cannot remove a newer
// one.
//
// A slot whose expiry or record Keeper cannot trust is kept and reported as
// slot_without_expiry_kept; only the confirmed archive_session_discard
// removes it. The device-wide slot of a Keeper before lv90 is never touched
// here.
func HandleArchiveSessionEnd(d Deps, req proto.ArchiveSessionEndRequest) proto.BaseResponse {
	d.Logger.Println("archive session end processing...")
	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}

	var response proto.BaseResponse
	_ = withArchiveSessionSlotLock(d, func() error {
		response = endArchiveSessionLocked(d, req)
		return nil
	})
	return response
}

func endArchiveSessionLocked(d Deps, req proto.ArchiveSessionEndRequest) proto.BaseResponse {
	slot, err := inspectArchiveSessionSlotLocked(d, req.OrgID, nil)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "read archive session slot failed")
	}
	present := slot.state != archiveSessionSlotAbsent
	if present && req.Fingerprint != "" && slot.fingerprint != req.Fingerprint {
		return proto.BaseResponse{Success: true, Data: proto.ArchiveSessionEndResponseData{Ended: false}}
	}
	if present && !slot.state.trusted() {
		return proto.BaseResponse{Success: true, Data: proto.ArchiveSessionEndResponseData{SlotWithoutExpiryKept: true}}
	}

	deleteArchiveSessionSlot(d, req.OrgID)
	return proto.BaseResponse{Success: true, Data: proto.ArchiveSessionEndResponseData{Ended: present}}
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
	// Under the lock, so a begin in another process sees the slot either
	// present or gone, never half deleted.
	var present bool
	var refusal proto.BaseResponse
	_ = withArchiveSessionSlotLock(d, func() error {
		var err error
		present, err = keychain.LegacyArchiveSessionPresent(d.Store)
		if err != nil {
			refusal = errs.CodeResponse(errs.ErrCodeStorageFailure, "read device-wide archive session slot failed")
			return nil
		}
		if err := keychain.DeleteLegacyArchiveSessionKeys(d.Store); err != nil {
			refusal = errs.CodeResponse(errs.ErrCodeStorageFailure, "delete device-wide archive session slot failed")
		}
		return nil
	})
	if refusal.ErrorCode != "" {
		return refusal
	}
	if present {
		d.Logger.Println("archive session legacy discard: device-wide session slot deleted on confirmed request")
	}
	return proto.BaseResponse{Success: true, Data: proto.ArchiveSessionLegacyDiscardResponseData{Discarded: present}}
}

// SweepExpiredArchiveSession runs once when the Keeper process starts,
// before it serves any action, so a session key left by a crash or a lost
// App is destroyed as soon as its expiry has passed even if nothing ever
// uses or ends it. It deletes only an organization slot whose record and
// expiry Keeper trusts; an expiry-unknown or unowned slot, and the
// device-wide slot of a Keeper before lv90, are left in place.
func SweepExpiredArchiveSession(d Deps) {
	_ = withArchiveSessionSlotLock(d, func() error {
		orgs, err := keychain.ListArchiveSessionOrgs(d.Store)
		if err != nil {
			// Uses still refuse an expired slot on their own clock.
			d.Logger.Println("archive session: startup sweep skipped, session index unreadable")
			return nil
		}
		for _, orgID := range orgs {
			sweepArchiveSessionSlotLocked(d, orgID)
		}
		return nil
	})
}

// sweepArchiveSessionSlotLocked deletes orgID's slot when it is trusted and
// expired, and drops an index entry whose slot holds no private record. The
// caller holds the lock.
func sweepArchiveSessionSlotLocked(d Deps, orgID string) {
	slot, err := inspectArchiveSessionSlotLocked(d, orgID, nil)
	if err != nil {
		return
	}
	switch slot.state {
	case archiveSessionSlotAbsent:
		deleteArchiveSessionSlot(d, orgID)
	case archiveSessionSlotExpired:
		deleteArchiveSessionSlot(d, orgID)
		d.Logger.Println("archive session: expired session key destroyed at startup")
	}
}

func formatArchiveSessionExpiry(t time.Time) string {
	return t.UTC().Format(time.RFC3339)
}
