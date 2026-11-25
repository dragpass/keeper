package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"

	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// The separate stage journal binds the candidate's private record to the
// original source key and round even if the candidate header is lost.
func supplementBinding(r proto.SupplementPrepare, prior archiveSessionSlot, recordHash [sha256.Size]byte) string {
	fields := []string{
		"supplement-binding-v1", r.OrgID, r.OperationID, r.ConfigDigest,
		r.PreviousSessionID, r.PreviousSPKI, strconv.Itoa(r.PreviousRound),
		hex.EncodeToString(prior.keyDigest[:]), hex.EncodeToString(recordHash[:]),
	}
	return publicDigest(strings.Join(fields, "|"))
}

// Called with the cross-process keychain lock held. Only return a snapshot
// after independently attributing the private item to this login and stage.
func supplementDamageLocked(d Deps, r proto.SupplementPrepare) proto.BaseResponse {
	j, target, err := supplementContext(d, r.SupplementPrevious)
	if err != nil || j.ProofSessionID != r.PreviousSessionID || j.ProofSessionSPKI != r.PreviousSPKI || j.ProofRound != r.PreviousRound {
		return rotationRefused()
	}
	prior, err := inspectArchiveSessionSlotLocked(d, r.OrgID, nil)
	if err != nil {
		return supplementStorageFailure()
	}
	if prior.state != archiveSessionSlotLive {
		return rotationRefused()
	}
	owner, err := archiveSessionCaller(d, prior)
	if err != nil {
		return archiveOwnerRefusal(err)
	}
	raw, err := keychain.GetArchiveSessionPrivateKey(d.Store, supplementSlot(r.OrgID))
	if errors.Is(err, keychain.ErrSecretNotFound) {
		return rotationRefused()
	}
	if err != nil {
		return supplementStorageFailure()
	}
	header, err := keychain.GetArchiveSessionPublicKey(d.Store, supplementSlot(r.OrgID))
	missing := errors.Is(err, keychain.ErrSecretNotFound)
	if err != nil && !missing {
		return supplementStorageFailure()
	}
	rec, _, ok := decodeArchiveSessionSlot(raw)
	preserved := proto.BaseResponse{Success: true, Data: proto.SupplementDamage{State: "preserved"}}
	if ok && rec.owner.account != "" && rec.owner != owner {
		return rotationRefused()
	}
	if !ok || rec.owner != owner || !archiveSessionRecordConsistent(rec, d.Now()) {
		return preserved
	}
	c, _, secret, err := decodeSupplement(d, r.OrgID, raw, header)
	if secret != nil {
		secret.Destroy()
	}
	if err == nil {
		if c.SupplementPrevious != r.SupplementPrevious || c.Round != r.PreviousRound {
			return preserved
		}
		return proto.BaseResponse{Success: true, Data: proto.SupplementDamage{State: "healthy"}}
	}
	if !errors.Is(err, errSupplementUnreadable) {
		return supplementStorageFailure()
	}
	if (c.OrgID != "" && c.OrgID != r.OrgID) ||
		(c.OperationID != "" && c.OperationID != r.OperationID) ||
		(c.Device != "" && c.Device != target.owner.device) ||
		(c.ConfigDigest != "" && c.ConfigDigest != r.ConfigDigest) ||
		(c.PreviousSessionID != "" && c.PreviousSessionID != r.PreviousSessionID) ||
		(c.PreviousSPKI != "" && c.PreviousSPKI != r.PreviousSPKI) {
		return preserved
	}
	binding := supplementBinding(r, prior, sha256.Sum256([]byte(raw)))
	if j.SupplementBinding != binding {
		return preserved
	}
	snapshot := publicDigest(strings.Join([]string{"supplement-discard-v1", binding, strconv.FormatBool(missing), publicDigest(header)}, "|"))
	return proto.BaseResponse{Success: true, Data: proto.SupplementDamage{State: "discardable", StoredDigest: snapshot}}
}

func HandleSupplementDamageStatus(d Deps, r proto.SupplementPrepare) proto.BaseResponse {
	if r.Validate() != nil {
		return rotationRefused()
	}
	return underStageLock(d.Store, func() proto.BaseResponse { return supplementDamageLocked(d, r) })
}

func HandleSupplementDiscard(d Deps, r proto.SupplementDiscard) proto.BaseResponse {
	if r.Validate() != nil {
		return rotationRefused()
	}
	return underStageLock(d.Store, func() proto.BaseResponse {
		res := supplementDamageLocked(d, r.SupplementPrepare)
		if !res.Success {
			return res
		}
		status := res.Data.(proto.SupplementDamage)
		if status.State != "discardable" || status.StoredDigest != r.StoredDigest {
			return rotationRefused()
		}
		if eraseSupplement(d, r.OrgID) != nil {
			return supplementStorageFailure()
		}
		return proto.BaseResponse{Success: true, Data: proto.SupplementDamage{State: "discarded"}}
	})
}
