package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/awnumar/memguard"

	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// A supplementary round's candidate session key is held in two keychain
// items beside the org's live session slot, in the session slot's own
// two-item layout, so each item stays within the smallest platform limit:
//
//   - org_archive_session_private_key:<org>:supplement holds the v3 session
//     record (owner, times, fingerprint) and the candidate private key PEM;
//   - org_archive_session_public_key:<org>:supplement holds the header: the
//     request it answers, the round, digests of the prior session's private
//     and public halves, the originating device and the candidate public key.
//
// The header is written before the private item and deleted after it, so
// an interruption leaves either no private key (a header alone, which holds
// no secret and is overwritten by the next prepare or removed by the sweep)
// or a complete candidate. Its private half is never usable by an archive
// operation until a signed acceptance authorizes copying it into the active
// session slot.
type supplementCandidate struct {
	V int `json:"v"`
	proto.SupplementPrevious
	proto.SupplementCandidate
	Round             int    `json:"round"`
	PriorDigest       string `json:"prior_digest"`
	PriorPublicDigest string `json:"prior_public_digest"`
	Device            string `json:"device"`
}

const supplementHeaderVersion = 1

// errSupplementUnreadable: a candidate private item exists but its header is
// missing or does not match it. Nothing that cannot be identified is
// automatically deleted. Explicit discard requires independent stage evidence.
var errSupplementUnreadable = errors.New("supplement candidate unreadable")

func supplementSlot(org string) string { return org + ":supplement" }

func publicDigest(pem string) string {
	sum := sha256.Sum256([]byte(pem))
	return hex.EncodeToString(sum[:])
}

// readSupplement returns the candidate with its private key PEM in a locked
// buffer the caller destroys. The keychain returns the record as a Go string,
// which cannot be wiped; only the copy handed on is.
func readSupplement(d Deps, org string) (supplementCandidate, archiveSessionRecord, *memguard.LockedBuffer, error) {
	var c supplementCandidate
	var rec archiveSessionRecord
	raw, err := keychain.GetArchiveSessionPrivateKey(d.Store, supplementSlot(org))
	if err != nil {
		return c, rec, nil, err
	}
	header, err := keychain.GetArchiveSessionPublicKey(d.Store, supplementSlot(org))
	if errors.Is(err, keychain.ErrSecretNotFound) {
		return c, rec, nil, errSupplementUnreadable
	}
	if err != nil {
		return c, rec, nil, err
	}
	return decodeSupplement(d, org, raw, header)
}

func decodeSupplement(d Deps, org, raw, header string) (supplementCandidate, archiveSessionRecord, *memguard.LockedBuffer, error) {
	var c supplementCandidate
	var rec archiveSessionRecord
	if json.Unmarshal([]byte(header), &c) != nil || c.V != supplementHeaderVersion || c.OrgID != org {
		return c, rec, nil, errSupplementUnreadable
	}
	if c.SupplementPrevious.Validate() != nil || !isLowerUUID(c.Device) || c.Round < 0 ||
		!isLowerHex64(c.PriorDigest) || !isLowerHex64(c.PriorPublicDigest) {
		return c, rec, nil, errSupplementUnreadable
	}
	if spki, err := crypto.RewrapKeyFingerprint(c.PublicKey); err != nil || spki != c.SPKI {
		return c, rec, nil, errSupplementUnreadable
	}
	rec, pem, ok := decodeArchiveSessionSlot(raw)
	if !ok || rec.fingerprint != fingerprintBase64Public(c.PublicKey) || !archiveSessionRecordConsistent(rec, d.Now()) {
		return c, rec, nil, errSupplementUnreadable
	}
	// The record's fingerprint field and the private key itself are checked
	// separately against the header: a candidate is returned, promoted or
	// swept only when all three name the same key.
	secret := memguard.NewBufferFromBytes([]byte(pem))
	if !privateMatchesPublic(secret.Bytes(), c.PublicKey) {
		secret.Destroy()
		return c, rec, nil, errSupplementUnreadable
	}
	return c, rec, secret, nil
}

func privateMatchesPublic(privatePEM []byte, public string) bool {
	key, err := parseRotationPrivate(privatePEM)
	if err != nil {
		return false
	}
	defer clearRotationPrivate(key)
	derived, err := crypto.PublicKeyToPEM(&key.PublicKey)
	return err == nil && derived == public
}
func supplementContext(d Deps, r proto.SupplementPrevious) (archiveReconfigurationJournal, rotationTarget, error) {
	target, err := readRotationTarget(d, proto.ArchiveRotationRequest{OrgID: r.OrgID, OperationID: r.OperationID, ConfigDigest: r.ConfigDigest})
	if err != nil {
		return archiveReconfigurationJournal{}, target, err
	}
	j, err := readStageJournal(d.Store, r.OrgID)
	return j, target, err
}

// writeSupplement stores a candidate: index entry, header, then private item.
func writeSupplement(d Deps, org string, header []byte, record []byte) error {
	if err := keychain.AddArchiveSessionOrg(d.Store, supplementSlot(org)); err != nil {
		return err
	}
	if err := keychain.SaveArchiveSessionPublicKey(d.Store, supplementSlot(org), string(header)); err != nil {
		return err
	}
	return keychain.SaveArchiveSessionPrivateKey(d.Store, supplementSlot(org), string(record))
}

// eraseSupplement deletes the private item first and the header second; a
// failure of either stops and is reported (errArchiveSessionDeleteFailed).
// A failed private delete leaves the complete candidate; a failed header
// delete leaves only the header, which holds no secret. The index entry is
// removed last and a failure there is not reported: the sweep drops an entry
// whose candidate holds no private item.
func eraseSupplement(d Deps, org string) error {
	if err := keychain.DeleteArchiveSessionPrivateKey(d.Store, supplementSlot(org)); err != nil && !errors.Is(err, keychain.ErrSecretNotFound) {
		return errArchiveSessionDeleteFailed
	}
	if err := keychain.DeleteArchiveSessionPublicKey(d.Store, supplementSlot(org)); err != nil && !errors.Is(err, keychain.ErrSecretNotFound) {
		return errArchiveSessionDeleteFailed
	}
	_ = keychain.RemoveArchiveSessionOrg(d.Store, supplementSlot(org))
	return nil
}

func supplementStorageFailure() proto.BaseResponse {
	return errs.CodeResponse(errs.ErrCodeStorageFailure, "supplement candidate storage failed")
}
func HandleSupplementPrepare(d Deps, r proto.SupplementPrepare) proto.BaseResponse {
	if err := r.Validate(); err != nil {
		return errs.Response(err)
	}
	var pair *crypto.KeyPair
	var private *memguard.LockedBuffer
	var generate bool
	decide := func() proto.BaseResponse {
		j, t, err := supplementContext(d, r.SupplementPrevious)
		if err != nil || j.ProofSessionID != r.PreviousSessionID || j.ProofSessionSPKI != r.PreviousSPKI || j.ProofRound != r.PreviousRound {
			return rotationRefused()
		}
		prior, err := inspectArchiveSessionSlotLocked(d, r.OrgID, nil)
		if err != nil || prior.state != archiveSessionSlotLive {
			return rotationRefused()
		}
		owner, err := archiveSessionCaller(d, prior)
		if err != nil {
			return archiveOwnerRefusal(err)
		}
		fp, err := crypto.RewrapKeyFingerprint(prior.publicKey)
		if err != nil || fp != r.PreviousSPKI {
			return rotationRefused()
		}
		c, rec, secret, err := readSupplement(d, r.OrgID)
		if secret != nil {
			secret.Destroy()
		}
		if err == nil && !d.Now().Before(rec.expiresAt) {
			if eraseSupplement(d, r.OrgID) != nil {
				return supplementStorageFailure()
			}
			err = keychain.ErrSecretNotFound
		}
		priorDigest := hex.EncodeToString(prior.keyDigest[:])
		if err == nil {
			if c.SupplementPrevious != r.SupplementPrevious || c.Round != r.PreviousRound || c.Device != t.owner.device || c.PriorDigest != priorDigest || c.PriorPublicDigest != publicDigest(prior.publicKey) || rec.owner != owner {
				return rotationRefused()
			}
			return proto.BaseResponse{Success: true, Data: c.SupplementCandidate}
		}
		if !errors.Is(err, keychain.ErrSecretNotFound) {
			return rotationRefused()
		}
		if pair == nil {
			generate = true
			return proto.BaseResponse{Success: true}
		}
		candidateFP, err := crypto.RewrapKeyFingerprint(pair.PublicKey)
		if err != nil || candidateFP == fp {
			return rotationRefused()
		}
		c = supplementCandidate{V: supplementHeaderVersion, SupplementPrevious: r.SupplementPrevious, SupplementCandidate: proto.SupplementCandidate{PublicKey: pair.PublicKey, SPKI: candidateFP}, Round: r.PreviousRound, PriorDigest: priorDigest, PriorPublicDigest: publicDigest(prior.publicKey), Device: t.owner.device}
		header, err := json.Marshal(c)
		if err != nil {
			return rotationRefused()
		}
		now := d.Now()
		// No begin_id: a begin resend never replays a promoted candidate.
		rec = archiveSessionRecord{owner: owner, begunAt: now, expiresAt: now.Add(archiveSessionMaxTTL), fingerprint: fingerprintBase64Public(pair.PublicKey)}
		record := encodeArchiveSessionSlot(rec, private.Bytes())
		defer record.Destroy()
		j.SupplementBinding = supplementBinding(r, prior, sha256.Sum256(record.Bytes()))
		if writeArchiveReconfigurationJournal(d.Store, j) != nil {
			return supplementStorageFailure()
		}
		if err := writeSupplement(d, r.OrgID, header, record.Bytes()); err != nil {
			return supplementStorageFailure()
		}
		return proto.BaseResponse{Success: true, Data: c.SupplementCandidate}
	}
	res := underStageLock(d.Store, decide)
	if !res.Success || !generate {
		return res
	}
	var err error
	pair, err = archiveSessionKeygen()
	if err != nil {
		return rotationRefused()
	}
	// The generator returns the PEM as a Go string, which cannot be wiped;
	// the reference is dropped and only the locked copy is used.
	private = memguard.NewBufferFromBytes([]byte(pair.PrivateKey))
	pair.PrivateKey = ""
	defer private.Destroy()
	return underStageLock(d.Store, decide)
}
func HandleSupplementPromote(d Deps, r proto.SupplementPromote) proto.BaseResponse {
	a := r.Receipt
	if r.Validate() != nil || d.ServerKeyVerifier == nil || d.ServerKeyVerifier.Verify(a.Canonical(), a.Signature, a.Version) != nil {
		return rotationRefused()
	}
	return underStageLock(d.Store, func() proto.BaseResponse {
		j, t, err := supplementContext(d, a.SupplementPrevious)
		if err != nil || t.owner.account != a.AccountID || t.owner.device != a.DeviceID || d.Now().Unix() >= a.ExpiresAt {
			return rotationRefused()
		}
		receiptFacts := a
		receiptFacts.Version = 0
		accepted := sha256.Sum256([]byte(receiptFacts.Canonical()))
		acceptanceDigest := hex.EncodeToString(accepted[:])
		success := proto.BaseResponse{Success: true, Data: proto.SupplementPromoted{SessionID: a.SessionID, SPKI: a.SPKI, Round: a.Round}}
		slot, err := inspectArchiveSessionSlotLocked(d, a.OrgID, nil)
		if err != nil {
			return rotationRefused()
		}
		owner, err := archiveSessionCaller(d, slot)
		if err != nil {
			return archiveOwnerRefusal(err)
		}
		if j.ProofSessionID == a.SessionID && j.ProofSessionSPKI == a.SPKI && j.ProofRound == a.Round {
			fp, err := crypto.RewrapKeyFingerprint(slot.publicKey)
			if err != nil || fp != a.SPKI || slot.state != archiveSessionSlotLive || j.ProofAcceptance != acceptanceDigest {
				return rotationRefused()
			}
			// A later prepare may already have stored its own candidate.
			c, _, secret, err := readSupplement(d, a.OrgID)
			if secret != nil {
				secret.Destroy()
			}
			if err == nil && c.SPKI == a.SPKI && eraseSupplement(d, a.OrgID) != nil {
				return supplementStorageFailure()
			}
			if err != nil && !errors.Is(err, keychain.ErrSecretNotFound) {
				return rotationRefused()
			}
			return success
		}
		if j.ProofSessionID != a.PreviousSessionID || j.ProofSessionSPKI != a.PreviousSPKI || j.ProofRound != a.Round-1 {
			return rotationRefused()
		}
		c, rec, secret, err := readSupplement(d, a.OrgID)
		if secret != nil {
			defer secret.Destroy()
		}
		if err != nil || c.SupplementPrevious != a.SupplementPrevious || c.SPKI != a.SPKI || c.Device != a.DeviceID || c.Round != a.Round-1 || rec.owner != owner || !d.Now().Before(rec.expiresAt) {
			return rotationRefused()
		}
		// Private first, public second. If a write was interrupted, accept only
		// the exact candidate private bytes with the prior or candidate public
		// half. An intervening begin, end or replacement is never overwritten.
		candidateDigest := sha256.Sum256(secret.Bytes())
		priorPublic := publicDigest(slot.publicKey) == c.PriorPublicDigest
		oldHalf := hex.EncodeToString(slot.keyDigest[:]) == c.PriorDigest && priorPublic && slot.state == archiveSessionSlotLive
		newHalf := slot.keyDigest == candidateDigest && (priorPublic || slot.publicKey == c.PublicKey)
		if !oldHalf && !newHalf {
			return rotationRefused()
		}
		if rec.expiresAt.Unix() > a.ExpiresAt {
			rec.expiresAt = time.Unix(a.ExpiresAt, 0).UTC()
		}
		if newHalf && slot.record.expiresAt.Before(rec.expiresAt) {
			rec.expiresAt = slot.record.expiresAt
		}
		if !d.Now().Before(rec.expiresAt) {
			return rotationRefused()
		}
		if !newHalf {
			record := encodeArchiveSessionSlot(rec, secret.Bytes())
			defer record.Destroy()
			if keychain.SaveArchiveSessionPrivateKey(d.Store, a.OrgID, string(record.Bytes())) != nil {
				return rotationRefused()
			}
		}
		if slot.publicKey != c.PublicKey && keychain.SaveArchiveSessionPublicKey(d.Store, a.OrgID, c.PublicKey) != nil {
			return rotationRefused()
		}
		j.SupplementBinding = ""
		j.ProofSessionID, j.ProofSessionSPKI, j.ProofRound, j.ProofAcceptance = a.SessionID, a.SPKI, a.Round, acceptanceDigest
		if writeArchiveReconfigurationJournal(d.Store, j) != nil {
			return rotationRefused()
		}
		if eraseSupplement(d, a.OrgID) != nil {
			return supplementStorageFailure()
		}
		if !d.Now().Before(rec.expiresAt) {
			return rotationRefused()
		}
		return success
	})
}

// Called only for names in the candidate namespace. Live and unreadable
// candidates are preserved throughout server response loss. A header without
// a private item holds no secret and is removed.
func sweepSupplementCandidate(d Deps, org string) {
	candidate, rec, secret, err := readSupplement(d, org)
	if secret != nil {
		defer secret.Destroy()
	}
	if errors.Is(err, keychain.ErrSecretNotFound) {
		_ = eraseSupplement(d, org)
		return
	}
	if err != nil {
		if errors.Is(err, errSupplementUnreadable) {
			d.Logger.Println("archive session: an unreadable supplement candidate is kept")
		}
		return
	}
	now := d.Now()
	slot, err := inspectArchiveSessionSlotLocked(d, org, nil)
	if err != nil {
		return
	}
	// An interrupted acceptance may leave the old public half beside the
	// expired candidate private record. A generic sweep preserves that
	// mismatch. Only this stored candidate can identify its exact bytes.
	if publicDigest(slot.publicKey) == candidate.PriorPublicDigest && slot.keyDigest == sha256.Sum256(secret.Bytes()) &&
		slot.record.owner == rec.owner && slot.record.fingerprint == rec.fingerprint &&
		slot.record.beginID == rec.beginID && archiveSessionRecordConsistent(slot.record, now) && !now.Before(slot.record.expiresAt) {
		if deleteArchiveSessionSlot(d, org) != nil {
			return
		}
	}
	if !now.Before(rec.expiresAt) {
		_ = eraseSupplement(d, org)
	}
}
