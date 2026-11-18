// archive_quorum_session.go — recovery-session keypair lifecycle.
//
// Part of the org archive-key admin quorum (Shamir N-of-M break-glass) flow;
// see archive_quorum_combine.go for the flow overview. The coordinator opens an
// ephemeral session keypair whose public key admins re-wrap their shares to
// (HandleArchiveShareRewrap), and whose private key reconstructs the archive
// key (HandleArchiveQuorumCombineAndRewrap). This file owns that keypair's
// begin/expiry/end/discard/status lifecycle and the sweeps;
// archive_session_slot.go owns the slot record and its trust and expiry
// rules.
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
// discard, status (which reports its presence), combine and the sweeps leave
// it alone; only archive_session_legacy_discard, which the App calls after
// the user confirms, deletes it.
//
// Key-material discipline: the session private key is held in a memguard buffer
// and the plaintext keypair string is wiped (secure.WipeString) once persisted;
// it never appears in a response.

package handlers

import (
	"context"
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
// slot's expiry (begin + archiveSessionMaxTTL). See
// decideArchiveSessionBeginLocked for when it writes, replays or refuses.
// Other organizations' sessions are untouched.
func HandleArchiveSessionBegin(d Deps, req proto.ArchiveSessionBeginRequest) proto.BaseResponse {
	d.Logger.Println("archive session begin processing...")
	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}

	// A begin the slot already refuses or replays generates no key.
	var decision archiveSessionBeginDecision
	err := withArchiveSessionSlotLock(d, func() error {
		var err error
		decision, err = decideArchiveSessionBeginLocked(d, req)
		return err
	})
	if err != nil || decision.step != archiveSessionBeginWrite {
		return archiveSessionBeginAnswer(d, decision, err)
	}

	// RSA generation runs outside the lock (it can take long enough to hold
	// up every other keychain lock user), so the decision is taken again
	// under the lock right before the write, on a fresh read: a begin, end or
	// sweep that ran meanwhile is seen, and a key that lost the race is not
	// stored.
	keyPair, err := archiveSessionKeygen()
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
		beginID:     req.BeginID,
	}
	record := encodeArchiveSessionSlot(rec, privBuf.Bytes())
	defer record.Destroy()

	err = withArchiveSessionSlotLock(d, func() error {
		var err error
		decision, err = decideArchiveSessionBeginLocked(d, req)
		if err != nil || decision.step != archiveSessionBeginWrite {
			return err
		}
		return writeArchiveSessionSlotLocked(d, req.OrgID, keyPair.PublicKey, record.Bytes())
	})
	if err != nil || decision.step != archiveSessionBeginWrite {
		return archiveSessionBeginAnswer(d, decision, err)
	}

	d.Logger.Println("archive session begin: ephemeral keypair created")
	return archiveSessionBeginResponse(keyPair.PublicKey, rec, false)
}

// archiveSessionBeginAnswer answers a begin that did not write: an error, a
// refusal or a replay.
func archiveSessionBeginAnswer(d Deps, decision archiveSessionBeginDecision, err error) proto.BaseResponse {
	if errors.Is(err, errArchiveSessionLegacySlotPresent) {
		return errs.CodeResponse(errs.ErrCodeArchiveSessionLegacySlotPresent, "a device-wide archive recovery session key from an earlier Keeper is present")
	}
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeStorageFailure, err.Error())
	}
	if decision.step == archiveSessionBeginReplay {
		d.Logger.Println("archive session begin: resend answered with the live session")
		return archiveSessionBeginResponse(decision.slot.publicKey, decision.slot.record, true)
	}
	return decision.refusal
}

// archiveSessionKeygen generates the session keypair. A variable only so
// tests can pin what happens while a begin generates its key.
var archiveSessionKeygen = crypto.GenerateRSAKeyPair

func archiveSessionBeginResponse(publicKey string, rec archiveSessionRecord, replayed bool) proto.BaseResponse {
	return proto.BaseResponse{Success: true, Data: proto.ArchiveSessionBeginResponseData{
		SessionPublicKey: publicKey,
		Fingerprint:      rec.fingerprint,
		ExpiresAt:        formatArchiveSessionExpiry(rec.expiresAt),
		BegunAt:          formatArchiveSessionExpiry(rec.begunAt),
		Replayed:         replayed,
	}}
}

type archiveSessionBeginStep int

const (
	archiveSessionBeginWrite archiveSessionBeginStep = iota
	archiveSessionBeginReplay
	archiveSessionBeginRefuse
)

type archiveSessionBeginDecision struct {
	step    archiveSessionBeginStep
	slot    archiveSessionSlot
	refusal proto.BaseResponse
}

// archiveSessionOwnerRefusal is the step that will judge whether the caller
// may act on a slot it has read: the account boundary. begin, set_expiry,
// end, discard and status run it on the slot they read, under the lock,
// before any branch that reuses, reports, changes or deletes the slot, the
// expiry delete included. The combine does not yet: its comparison of the
// slot with the server decision's account comes with the account boundary
// change. This version has no owner to compare and admits every slot, so a
// begin_id resend is matched on the organization and begin_id alone; that
// is interim, and the account condition is added here. A variable so tests
// can pin the order.
var archiveSessionOwnerRefusal = func(Deps, string, archiveSessionSlot) (proto.BaseResponse, bool) {
	return proto.BaseResponse{}, false
}

// decideArchiveSessionBeginLocked decides what a begin does with req.OrgID's
// slot. In order: the device-wide slot of a Keeper before lv90 refuses
// (errArchiveSessionLegacySlotPresent); the owner step may refuse; an absent
// slot, or a trusted one whose expiry has passed, is written; a live slot
// whose begin_id equals the request's non-empty begin_id is replayed; any
// other slot (a live session of another or no begin_id, an expiry-unknown or
// unowned slot) is refused with archive_session_active and kept. The caller
// holds the lock; nothing here writes.
func decideArchiveSessionBeginLocked(d Deps, req proto.ArchiveSessionBeginRequest) (archiveSessionBeginDecision, error) {
	// The device-wide slot of a Keeper before lv90 may hold the key of an
	// in-flight recovery session of an organization this Keeper cannot name.
	// It is never deleted, moved or used here; the App asks the user, then
	// calls archive_session_legacy_discard.
	present, err := keychain.LegacyArchiveSessionPresent(d.Store)
	if err != nil {
		return archiveSessionBeginDecision{}, errors.New("read device-wide archive session slot failed")
	}
	if present {
		return archiveSessionBeginDecision{}, errArchiveSessionLegacySlotPresent
	}
	slot, err := inspectArchiveSessionSlotLocked(d, req.OrgID, nil)
	if err != nil {
		return archiveSessionBeginDecision{}, errors.New("read archive session slot failed")
	}
	if refusal, refused := archiveSessionOwnerRefusal(d, req.OrgID, slot); refused {
		return archiveSessionBeginDecision{step: archiveSessionBeginRefuse, refusal: refusal}, nil
	}
	switch slot.state {
	case archiveSessionSlotAbsent, archiveSessionSlotExpired:
		return archiveSessionBeginDecision{step: archiveSessionBeginWrite, slot: slot}, nil
	case archiveSessionSlotLive:
		if req.BeginID != "" && req.BeginID == slot.record.beginID {
			return archiveSessionBeginDecision{step: archiveSessionBeginReplay, slot: slot}, nil
		}
	}
	return archiveSessionBeginDecision{step: archiveSessionBeginRefuse, refusal: archiveSessionActiveResponse(slot)}, nil
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
	data := proto.ArchiveSessionActiveData{Fingerprint: slot.fingerprint, StoredDigest: slot.storedDigest}
	switch slot.state {
	case archiveSessionSlotLive:
		data.State = proto.ArchiveSessionStateLive
		data.ExpiresAt = formatArchiveSessionExpiry(slot.record.expiresAt)
		data.BegunAt = formatArchiveSessionExpiry(slot.record.begunAt)
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
// req.Fingerprint. The fingerprint is compared first: a request naming
// another key is not_found and changes nothing, even on an expired slot.
// Then the slot is judged as at every use: an untrusted slot is refused and
// kept, an expired one deleted. The slot's expiry only moves earlier: a
// later or forged value leaves the Keeper-side bound in place.
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
		if r, refused := archiveSessionOwnerRefusal(d, req.OrgID, slot); refused {
			refusal = r
			return nil
		}
		if slot.state == archiveSessionSlotAbsent || slot.fingerprint != req.Fingerprint {
			refusal = errs.CodeResponse(errs.ErrCodeNotFound, "no archive session with this fingerprint")
			return nil
		}
		return useArchiveSessionSlotLocked(d, req.OrgID, slot, func() {
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
		if err := deleteArchiveSessionSlot(d, orgID); err != nil {
			return archiveSessionSlotResponse(err)
		}
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

// HandleArchiveSessionEnd destroys the recovery-session keypair of
// req.OrgID whose public key has req.Fingerprint. Idempotent: ended=false
// when the slot is empty or holds another key, so a late end for an earlier
// session never removes a newer one. A trusted slot with that key is
// deleted whether or not it has expired.
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
	if err := withArchiveSessionSlotLock(d, func() error {
		response = endArchiveSessionLocked(d, req)
		return nil
	}); err != nil {
		return archiveSessionLockFailure()
	}
	return response
}

func endArchiveSessionLocked(d Deps, req proto.ArchiveSessionEndRequest) proto.BaseResponse {
	slot, err := inspectArchiveSessionSlotLocked(d, req.OrgID, nil)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "read archive session slot failed")
	}
	if refusal, refused := archiveSessionOwnerRefusal(d, req.OrgID, slot); refused {
		return refusal
	}
	if slot.state == archiveSessionSlotAbsent || slot.fingerprint != req.Fingerprint {
		return proto.BaseResponse{Success: true, Data: proto.ArchiveSessionEndResponseData{Ended: false}}
	}
	if !slot.state.trusted() {
		return proto.BaseResponse{Success: true, Data: proto.ArchiveSessionEndResponseData{SlotWithoutExpiryKept: true}}
	}
	if err := deleteArchiveSessionSlot(d, req.OrgID); err != nil {
		return archiveSessionSlotResponse(err)
	}
	return proto.BaseResponse{Success: true, Data: proto.ArchiveSessionEndResponseData{Ended: true}}
}

// HandleArchiveSessionDiscard deletes req.OrgID's session keypair when, read
// under the lock at the moment of the delete, the slot's key has
// req.Fingerprint (or, for the one slot shape without a fingerprint, its
// stored bytes have req.StoredDigest): a live, expired, expiry-unknown or
// unowned slot alike.
// The App calls it only after the user confirmed losing whatever recovery
// attempt the key belongs to. When the slot holds another key (one begun
// after the confirmation) it is refused with archive_session_changed and
// nothing is deleted; an empty slot is discarded=false. Other
// organizations' slots and the device-wide slot are untouched.
func HandleArchiveSessionDiscard(d Deps, req proto.ArchiveSessionDiscardRequest) proto.BaseResponse {
	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}
	var response proto.BaseResponse
	if err := withArchiveSessionSlotLock(d, func() error {
		slot, err := inspectArchiveSessionSlotLocked(d, req.OrgID, nil)
		if err != nil {
			response = errs.CodeResponse(errs.ErrCodeStorageFailure, "read archive session slot failed")
			return nil
		}
		if refusal, refused := archiveSessionOwnerRefusal(d, req.OrgID, slot); refused {
			response = refusal
			return nil
		}
		if slot.state == archiveSessionSlotAbsent {
			response = proto.BaseResponse{Success: true, Data: proto.ArchiveSessionDiscardResponseData{Discarded: false}}
			return nil
		}
		if !archiveSessionDiscardNames(slot, req) {
			response = errs.CodeResponse(errs.ErrCodeArchiveSessionChanged, "the organization's archive session slot holds another key")
			return nil
		}
		if err := deleteArchiveSessionSlot(d, req.OrgID); err != nil {
			response = archiveSessionSlotResponse(err)
			return nil
		}
		d.Logger.Println("archive session discard: session key deleted on confirmed request")
		response = proto.BaseResponse{Success: true, Data: proto.ArchiveSessionDiscardResponseData{Discarded: true}}
		return nil
	}); err != nil {
		return archiveSessionLockFailure()
	}
	return response
}

// archiveSessionDiscardNames reports whether req names the key slot holds:
// by its fingerprint, or, for the one shape without a fingerprint, by the
// digest of its stored bytes.
func archiveSessionDiscardNames(slot archiveSessionSlot, req proto.ArchiveSessionDiscardRequest) bool {
	if req.StoredDigest != "" {
		return slot.fingerprint == "" && slot.storedDigest != "" && slot.storedDigest == req.StoredDigest
	}
	return slot.fingerprint != "" && slot.fingerprint == req.Fingerprint
}

// HandleArchiveSessionStatus reports req.OrgID's session slot. It only
// reads: no slot, index entry or expiry is written or deleted, an expired
// slot included. The state can change right after the read; every action
// that uses, ends or discards the slot reads and judges it again.
func HandleArchiveSessionStatus(d Deps, req proto.ArchiveSessionStatusRequest) proto.BaseResponse {
	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}
	var response proto.BaseResponse
	if err := withArchiveSessionSlotLock(d, func() error {
		legacy, err := keychain.LegacyArchiveSessionPresent(d.Store)
		if err != nil {
			response = errs.CodeResponse(errs.ErrCodeStorageFailure, "read device-wide archive session slot failed")
			return nil
		}
		slot, err := inspectArchiveSessionSlotLocked(d, req.OrgID, nil)
		if err != nil {
			response = errs.CodeResponse(errs.ErrCodeStorageFailure, "read archive session slot failed")
			return nil
		}
		if refusal, refused := archiveSessionOwnerRefusal(d, req.OrgID, slot); refused {
			response = refusal
			return nil
		}
		response = proto.BaseResponse{Success: true, Data: archiveSessionStatusData(slot, req.Fingerprint, legacy)}
		return nil
	}); err != nil {
		return archiveSessionLockFailure()
	}
	return response
}

func archiveSessionStatusData(slot archiveSessionSlot, fingerprint string, legacy bool) proto.ArchiveSessionStatusResponseData {
	data := proto.ArchiveSessionStatusResponseData{Fingerprint: slot.fingerprint, StoredDigest: slot.storedDigest, LegacySlotPresent: legacy}
	switch slot.state {
	case archiveSessionSlotAbsent:
		data.State = proto.ArchiveSessionStateAbsent
		data.Fingerprint = ""
	case archiveSessionSlotLive, archiveSessionSlotExpired:
		data.State = proto.ArchiveSessionStateLive
		if slot.state == archiveSessionSlotExpired {
			data.State = proto.ArchiveSessionStateExpired
		}
		data.ExpiresAt = formatArchiveSessionExpiry(slot.record.expiresAt)
		data.BegunAt = formatArchiveSessionExpiry(slot.record.begunAt)
	case archiveSessionSlotExpiryUnknown:
		data.State = proto.ArchiveSessionStateExpiryUnknown
	default:
		data.State = proto.ArchiveSessionStateUnowned
	}
	if fingerprint != "" {
		matches := data.Fingerprint != "" && data.Fingerprint == fingerprint
		data.FingerprintMatches = &matches
	}
	return data
}

// archiveSessionLockFailure answers an action that could not take the
// keychain process lock: it read and wrote nothing.
func archiveSessionLockFailure() proto.BaseResponse {
	return errs.CodeResponse(errs.ErrCodeStorageFailure, "keychain process lock unavailable")
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
	if err := withArchiveSessionSlotLock(d, func() error {
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
	}); err != nil {
		return archiveSessionLockFailure()
	}
	if refusal.ErrorCode != "" {
		return refusal
	}
	if present {
		d.Logger.Println("archive session legacy discard: device-wide session slot deleted on confirmed request")
	}
	return proto.BaseResponse{Success: true, Data: proto.ArchiveSessionLegacyDiscardResponseData{Discarded: present}}
}

// SweepExpiredArchiveSession runs when the Keeper process starts, before it
// serves any action, and then periodically (RunArchiveSessionSweeper), so a
// session key left by a crash or a lost App is destroyed once its expiry
// has passed even if nothing ever uses or ends it. It deletes only an
// organization slot whose record and expiry Keeper trusts; an
// expiry-unknown or unowned slot, and the device-wide slot of a Keeper
// before lv90, are left in place. Uses keep checking the expiry on their
// own; the sweep is not what the refusal depends on.
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
		if deleteArchiveSessionSlot(d, orgID) != nil {
			d.Logger.Println("archive session: sweep could not remove a leftover public half or index entry; retrying at the next sweep")
		}
	case archiveSessionSlotExpired:
		if deleteArchiveSessionSlot(d, orgID) != nil {
			d.Logger.Println("archive session: sweep could not delete an expired session key; retrying at the next sweep")
			return
		}
		d.Logger.Println("archive session: expired session key destroyed by the sweep")
	}
}

// RunArchiveSessionSweeper runs SweepExpiredArchiveSession on every tick
// until ctx is done. Each sweep holds the keychain process lock like every
// other session slot access.
func RunArchiveSessionSweeper(ctx context.Context, d Deps, ticks <-chan time.Time) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticks:
			SweepExpiredArchiveSession(d)
		}
	}
}

func formatArchiveSessionExpiry(t time.Time) string {
	return t.UTC().Format(time.RFC3339)
}
