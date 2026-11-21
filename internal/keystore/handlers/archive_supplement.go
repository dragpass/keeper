package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/secure"
)

// The candidate occupies one separately named keychain record. Its private
// half is never usable by an archive operation until a signed acceptance
// authorizes copying it into the active session slot.
type supplementCandidate struct {
	proto.SupplementPrevious
	proto.SupplementCandidate
	Round       int
	PriorDigest string
	PriorPublic string
	Device      string
}

func supplementSlot(org string) string { return org + ":supplement" }
func readSupplement(d Deps, org string) (supplementCandidate, archiveSessionRecord, string, error) {
	var c supplementCandidate
	var rec archiveSessionRecord
	raw, err := keychain.GetArchiveSessionPrivateKey(d.Store, supplementSlot(org))
	if err != nil {
		return c, rec, "", err
	}
	defer secure.WipeString(&raw)
	header, record, ok := strings.Cut(raw, "\n")
	if !ok || json.Unmarshal([]byte(header), &c) != nil || c.OrgID != org {
		return c, rec, "", errRotationUnavailable
	}
	rec, pem, ok := decodeArchiveSessionSlot(record)
	if !ok || rec.fingerprint != fingerprintBase64Public(c.PublicKey) || !archiveSessionRecordConsistent(rec, d.Now()) {
		return c, rec, "", errRotationUnavailable
	}
	return c, rec, pem, nil
}
func supplementContext(d Deps, r proto.SupplementPrevious) (archiveReconfigurationJournal, rotationTarget, error) {
	target, err := readRotationTarget(d, proto.ArchiveRotationRequest{OrgID: r.OrgID, OperationID: r.OperationID, ConfigDigest: r.ConfigDigest})
	if err != nil {
		return archiveReconfigurationJournal{}, target, err
	}
	j, err := readStageJournal(d.Store, r.OrgID)
	return j, target, err
}
func eraseSupplement(d Deps, org string) error {
	err := keychain.DeleteArchiveSessionPrivateKey(d.Store, supplementSlot(org))
	if err != nil && !errors.Is(err, keychain.ErrSecretNotFound) {
		return err
	}
	return keychain.RemoveArchiveSessionOrg(d.Store, supplementSlot(org))
}
func HandleSupplementPrepare(d Deps, r proto.SupplementPrepare) proto.BaseResponse {
	if err := r.Validate(); err != nil {
		return errs.Response(err)
	}
	var pair *crypto.KeyPair
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
		c, rec, pem, err := readSupplement(d, r.OrgID)
		defer secure.WipeString(&pem)
		if err == nil && !d.Now().Before(rec.expiresAt) {
			if eraseSupplement(d, r.OrgID) != nil {
				return rotationRefused()
			}
			err = keychain.ErrSecretNotFound
		}
		priorDigest := hex.EncodeToString(prior.keyDigest[:])
		if err == nil {
			if c.SupplementPrevious != r.SupplementPrevious || c.Round != r.PreviousRound || c.Device != t.owner.device || c.PriorDigest != priorDigest || rec.owner != owner {
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
		c = supplementCandidate{SupplementPrevious: r.SupplementPrevious, SupplementCandidate: proto.SupplementCandidate{PublicKey: pair.PublicKey, SPKI: candidateFP}, Round: r.PreviousRound, PriorDigest: priorDigest, PriorPublic: prior.publicKey, Device: t.owner.device}
		header, err := json.Marshal(c)
		if err != nil {
			return rotationRefused()
		}
		now := d.Now()
		rec = archiveSessionRecord{owner: owner, begunAt: now, expiresAt: now.Add(archiveSessionMaxTTL), fingerprint: fingerprintBase64Public(pair.PublicKey), beginID: r.PreviousSessionID}
		record := encodeArchiveSessionSlot(rec, []byte(pair.PrivateKey))
		defer record.Destroy()
		value := string(header) + "\n" + string(record.Bytes())
		defer secure.WipeString(&value)
		if err := keychain.AddArchiveSessionOrg(d.Store, supplementSlot(r.OrgID)); err != nil {
			return rotationRefused()
		}
		if err := keychain.SaveArchiveSessionPrivateKey(d.Store, supplementSlot(r.OrgID), value); err != nil {
			return rotationRefused()
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
	defer secure.WipeString(&pair.PrivateKey)
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
			defer secure.WipeString(&secret)
			if err == nil && c.SPKI == a.SPKI && eraseSupplement(d, a.OrgID) != nil {
				return rotationRefused()
			}
			if err != nil && !errors.Is(err, keychain.ErrSecretNotFound) {
				return rotationRefused()
			}
			return success
		}
		if j.ProofSessionID != a.PreviousSessionID || j.ProofSessionSPKI != a.PreviousSPKI || j.ProofRound != a.Round-1 {
			return rotationRefused()
		}
		c, rec, pem, err := readSupplement(d, a.OrgID)
		defer secure.WipeString(&pem)
		if err != nil || c.SupplementPrevious != a.SupplementPrevious || c.SPKI != a.SPKI || c.Device != a.DeviceID || c.Round != a.Round-1 || rec.owner != owner || !d.Now().Before(rec.expiresAt) {
			return rotationRefused()
		}
		private, err := parseRotationPrivate([]byte(pem))
		if err != nil {
			return rotationRefused()
		}
		defer clearRotationPrivate(private)
		pub, err := crypto.PublicKeyToPEM(&private.PublicKey)
		if err != nil || pub != c.PublicKey {
			return rotationRefused()
		}
		spki, err := crypto.RewrapKeyFingerprint(pub)
		if err != nil || spki != a.SPKI {
			return rotationRefused()
		}
		// Private first, public second. If a write was interrupted, accept only
		// the exact candidate private bytes with the prior or candidate public
		// half. An intervening begin, end or replacement is never overwritten.
		candidateDigest := sha256.Sum256([]byte(pem))
		oldHalf := hex.EncodeToString(slot.keyDigest[:]) == c.PriorDigest && slot.publicKey == c.PriorPublic && slot.state == archiveSessionSlotLive
		newHalf := slot.keyDigest == candidateDigest && (slot.publicKey == c.PriorPublic || slot.publicKey == c.PublicKey)
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
			record := encodeArchiveSessionSlot(rec, []byte(pem))
			defer record.Destroy()
			if keychain.SaveArchiveSessionPrivateKey(d.Store, a.OrgID, string(record.Bytes())) != nil {
				return rotationRefused()
			}
		}
		if slot.publicKey != c.PublicKey && keychain.SaveArchiveSessionPublicKey(d.Store, a.OrgID, c.PublicKey) != nil {
			return rotationRefused()
		}
		j.ProofSessionID, j.ProofSessionSPKI, j.ProofRound, j.ProofAcceptance = a.SessionID, a.SPKI, a.Round, acceptanceDigest
		if writeArchiveReconfigurationJournal(d.Store, j) != nil || eraseSupplement(d, a.OrgID) != nil {
			return rotationRefused()
		}
		if !d.Now().Before(rec.expiresAt) {
			return rotationRefused()
		}
		return success
	})
}

// Called only for names in the candidate namespace. Live and unreadable
// candidates are preserved throughout server response loss.
func sweepSupplementCandidate(d Deps, org string) {
	candidate, rec, pem, err := readSupplement(d, org)
	defer secure.WipeString(&pem)
	if errors.Is(err, keychain.ErrSecretNotFound) {
		_ = eraseSupplement(d, org)
		return
	}
	if err != nil {
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
	if slot.publicKey == candidate.PriorPublic && slot.keyDigest == sha256.Sum256([]byte(pem)) &&
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
