package handlers

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"github.com/awnumar/memguard"
	"math/big"
	"time"

	"github.com/dragpass/keeper/config"
	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/secure"
)

var errRotationUnavailable = errors.New("archive rotation unavailable")

type rotationTarget struct {
	public, spki, sourceSPKI, fingerprint string
	owner                                 stageOwner
	generation                            uint64
}

// Called under the keychain process lock. Only public material and journals
// may be read here, including on preparation and before challenge admission.
func readRotationTarget(d Deps, r proto.ArchiveRotationRequest) (rotationTarget, error) {
	var t rotationTarget
	owner, err := currentStageOwner(d)
	if err != nil {
		return t, err
	}
	stage, err := readStageJournal(d.Store, r.OrgID)
	if err != nil {
		return t, err
	}
	if !stageBelongsTo(stage, owner, r.OrgID) || stage.OperationID != r.OperationID || stage.Finalization != "" || stage.Closure != nil || stage.UnregisteredCleanup != "" {
		return t, errRotationUnavailable
	}
	slot := keychain.OrgArchiveReconfigurationSlot(r.OrgID)
	raw, err := d.Store.Get(config.Service, archiveSplitJournalAccount(slot))
	if err != nil {
		return t, err
	}
	var split archiveSplitJournal
	if json.Unmarshal([]byte(raw), &split) != nil {
		return t, errRotationUnavailable
	}
	b := split.Binding
	if split.State != "" || split.OperationID != r.OperationID || b.OrgID != r.OrgID || b.Kind != stage.Kind || b.AccountID != owner.account || b.ConfigDigest != r.ConfigDigest || split.KeyFingerprint != stage.TargetKeyFingerprint || b.TargetKeyFingerprint != stage.TargetKeyFingerprint {
		return t, errRotationUnavailable
	}
	pub, err := slot.GetPublic(d.Store)
	if err != nil {
		return t, err
	}
	spki, err := crypto.RewrapKeyFingerprint(pub)
	if err != nil || spki != b.ArchiveKeySPKIFingerprint || fingerprintBase64Public(pub) != stage.TargetKeyFingerprint || !isLowerHex64(b.ActiveKeySPKIFingerprint) || spki == b.ActiveKeySPKIFingerprint {
		return t, errRotationUnavailable
	}
	binding, _, err := keychain.GetAccountBinding(d.Store)
	if err != nil {
		return t, err
	}
	return rotationTarget{public: pub, spki: spki, sourceSPKI: b.ActiveKeySPKIFingerprint, fingerprint: stage.TargetKeyFingerprint, owner: owner, generation: binding.Generation}, nil
}
func rotationRefused() proto.BaseResponse {
	return errs.CodeResponse(errs.ErrCodeNotFound, errRotationUnavailable.Error())
}

func HandleArchiveRotationPrepare(d Deps, r proto.ArchiveRotationPrepare) proto.BaseResponse {
	if r.Validate() != nil || d.ArchiveRotationChallenges == nil {
		return rotationRefused()
	}
	return underStageLock(d.Store, func() proto.BaseResponse {
		target, err := readRotationTarget(d, r.Request)
		if err != nil {
			return rotationRefused()
		}
		commit, err := r.Request.Commitment(target.owner.account, target.spki)
		if err != nil {
			return errs.Response(err)
		}
		var random [32]byte
		if err := d.FillRandom(random[:]); err != nil {
			return rotationRefused()
		}
		challenge := base64.RawURLEncoding.EncodeToString(random[:])
		c := archiveShareContext{accountID: target.owner.account, deviceID: target.owner.device, bindingGeneration: target.generation, tokenID: r.TokenID, sessionStartNanos: r.SessionStart, requestDigest: commit.RequestDigest, orgID: r.Request.OrgID, operationID: r.Request.OperationID, recoverySessionID: r.Request.SessionID}
		if d.ArchiveRotationChallenges.Put(challenge, c, d.Now()) != nil {
			return rotationRefused()
		}
		return proto.BaseResponse{Success: true, Data: proto.RotationPrepared{Challenge: challenge, RequestDigest: c.requestDigest, TargetSPKI: target.spki}}
	})
}

func HandleArchiveQuorumCombineToStaged(d Deps, r proto.ArchiveRotationExecute) proto.BaseResponse {
	dec := r.Decision
	if r.Validate() != nil || d.ArchiveRotationChallenges == nil || d.ServerKeyVerifier == nil {
		return rotationRefused()
	}
	if err := d.ServerKeyVerifier.Verify(dec.Canonical(), dec.Signature, dec.Version); err != nil {
		return rotationRefused()
	}
	var target rotationTarget
	var deadline time.Time
	var session archiveSessionSlot
	var buf *memguard.LockedBuffer
	admitted := underStageLock(d.Store, func() proto.BaseResponse {
		var err error
		target, err = readRotationTarget(d, r.Request)
		if err != nil {
			return rotationRefused()
		}
		want, err := r.Request.Commitment(target.owner.account, target.spki)
		if err != nil {
			return rotationRefused()
		}
		if dec.AccountID != want.AccountID || dec.OrgID != want.OrgID || dec.SessionID != want.SessionID || dec.OperationID != want.OperationID || dec.ConfigDigest != want.ConfigDigest || dec.TargetSPKI != want.TargetSPKI || dec.SharesDigest != want.SharesDigest || dec.GrantsDigest != want.GrantsDigest || dec.RequestDigest != want.RequestDigest || dec.DeviceID != target.owner.device {
			return rotationRefused()
		}
		now := d.Now()
		if now.Unix() >= dec.ExpiresAt || dec.IssuedAt > now.Unix()+proto.DisplayDecisionClockSkewSeconds {
			return rotationRefused()
		}
		c := archiveShareContext{accountID: dec.AccountID, deviceID: dec.DeviceID, bindingGeneration: target.generation, tokenID: dec.TokenID, sessionStartNanos: dec.SessionStart, requestDigest: dec.RequestDigest, orgID: dec.OrgID, operationID: dec.OperationID, recoverySessionID: dec.SessionID}
		entry, ok := d.ArchiveRotationChallenges.peekEntry(dec.Challenge, now)
		if !ok || entry.context != c {
			return rotationRefused()
		}
		used, ok := d.ArchiveRotationChallenges.Consume(dec.Challenge, now)
		if !ok || used != c {
			return rotationRefused()
		}
		deadline = entry.expiresAt
		buf, session, err = openArchiveSessionSlotLocked(d, dec.OrgID, dec.AccountID)
		if err != nil {
			return archiveSessionSlotResponse(err)
		}
		return proto.BaseResponse{Success: true}
	})
	if !admitted.Success {
		return admitted
	}
	defer buf.Destroy()
	source, err := reconstructRotationSource(buf.Bytes(), r.Request.Shares, target.sourceSPKI)
	if err != nil {
		return rotationRefused()
	}
	defer clearRotationPrivate(source)
	pub, err := crypto.ParsePublicKey(target.public)
	if err != nil {
		return rotationRefused()
	}
	outputs := make([]proto.RotationGrantOutput, 0, len(r.Request.Grants))
	for _, g := range r.Request.Grants {
		out, err := rotateOneGrant(source, pub, dec.OrgID, g)
		if err != nil {
			return rotationRefused()
		}
		outputs = append(outputs, proto.RotationGrantOutput{ID: g.ID, Fingerprint: target.fingerprint, Wrapped: out})
	}
	return underStageLock(d.Store, func() proto.BaseResponse {
		current, err := readRotationTarget(d, r.Request)
		if err != nil || target != current {
			return rotationRefused()
		}
		if err := recheckArchiveSessionSlotForOutputLocked(d, dec.OrgID, session); err != nil {
			return archiveSessionSlotResponse(err)
		}
		now := d.Now()
		if !now.Before(deadline) || now.Unix() >= dec.ExpiresAt {
			return rotationRefused()
		}
		return proto.BaseResponse{Success: true, Data: proto.RotationOutputs{Grants: outputs}}
	})
}

func parseRotationPrivate(raw []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errRotationUnavailable
	}
	defer secure.Zeroize(block.Bytes)
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errRotationUnavailable
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, errRotationUnavailable
	}
	return rsaKey, nil
}

// Clear the private integer storage Go exposes. The RSA implementation may
// keep internal precomputations outside these fields until garbage collection.
func clearRotationPrivate(key *rsa.PrivateKey) {
	clearInt := func(x *big.Int) {
		if x != nil {
			clear(x.Bits())
		}
	}
	clearInt(key.D)
	for _, p := range key.Primes {
		clearInt(p)
	}
	clearInt(key.Precomputed.Dp)
	clearInt(key.Precomputed.Dq)
	clearInt(key.Precomputed.Qinv)
	for _, v := range key.Precomputed.CRTValues {
		clearInt(v.Exp)
		clearInt(v.Coeff)
		clearInt(v.R)
	}
	*key = rsa.PrivateKey{}
}

func reconstructRotationSource(sessionPEM []byte, rows []proto.RotationShare, sourceSPKI string) (*rsa.PrivateKey, error) {
	key, err := parseRotationPrivate(sessionPEM)
	if err != nil {
		return nil, err
	}
	defer clearRotationPrivate(key)
	shares := make([]crypto.Share, 0, len(rows))
	defer func() {
		for _, s := range shares {
			secure.Zeroize(s.Y)
		}
	}()
	for _, row := range rows {
		plain, err := crypto.HybridUnwrap(key, row.WrappedKey, row.Ciphertext)
		if err != nil {
			return nil, err
		}
		s, err := crypto.DeserializeShare(plain)
		secure.Zeroize(plain)
		if err != nil {
			return nil, err
		}
		shares = append(shares, s)
		if int(s.X) != row.Index {
			return nil, errRotationUnavailable
		}
	}
	secret, err := crypto.CombineShares(shares)
	if err != nil {
		return nil, err
	}
	defer secure.Zeroize(secret)
	source, err := parseRotationPrivate(secret)
	if err != nil {
		return nil, err
	}
	pub, err := crypto.PublicKeyToPEM(&source.PublicKey)
	if err != nil {
		clearRotationPrivate(source)
		return nil, err
	}
	fp, err := crypto.RewrapKeyFingerprint(pub)
	if err != nil || fp != sourceSPKI {
		clearRotationPrivate(source)
		return nil, errRotationUnavailable
	}
	return source, nil
}
func rotateOneGrant(source *rsa.PrivateKey, target *rsa.PublicKey, org string, g proto.RotationGrant) (string, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(g.Wrapped)
	if err != nil {
		return "", err
	}
	gc := g.Context(org)
	dek, err := unwrapGrant(source, ciphertext, gc)
	if err != nil {
		return "", err
	}
	defer secure.Zeroize(dek)
	if len(dek) != 32 {
		return "", errRotationUnavailable
	}
	output, err := wrapGrant(target, dek, gc)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(output), nil
}

func HandleArchiveReconfigurationSessionKeyProof(d Deps, r proto.ArchiveReconfigurationSessionKeyProof) proto.BaseResponse {
	if err := r.Validate(); err != nil {
		return errs.Response(err)
	}
	return underStageLock(d.Store, func() proto.BaseResponse {
		target, err := readRotationTarget(d, proto.ArchiveRotationRequest{OrgID: r.OrgID, OperationID: r.OperationID, ConfigDigest: r.ConfigDigest})
		if err != nil {
			return rotationRefused()
		}
		buf, session, err := openArchiveSessionSlotLocked(d, r.OrgID, target.owner.account)
		if err != nil {
			return archiveSessionSlotResponse(err)
		}
		defer buf.Destroy()
		key, err := parseRotationPrivate(buf.Bytes())
		if err != nil {
			return rotationRefused()
		}
		defer clearRotationPrivate(key)
		pub, err := crypto.PublicKeyToPEM(&key.PublicKey)
		if err != nil || pub != session.publicKey {
			return rotationRefused()
		}
		fp, err := crypto.RewrapKeyFingerprint(pub)
		if err != nil || fp != r.SessionSPKI {
			return rotationRefused()
		}
		journal, err := readStageJournal(d.Store, r.OrgID)
		if err != nil {
			return rotationRefused()
		}
		sameSession := journal.ProofSessionID == r.SessionID
		sameKey := journal.ProofSessionSPKI == fp
		if sameSession != sameKey || (!sameKey && journal.ProofSessionID != "") {
			return rotationRefused()
		}
		signed := signRequestCanonical(d, r.Canonical(target.owner.account, target.owner.device, fp))
		if !signed.Success {
			return signed
		}
		if err := recheckArchiveSessionSlotForOutputLocked(d, r.OrgID, session); err != nil {
			return archiveSessionSlotResponse(err)
		}
		if !sameSession {
			journal.ProofSessionID, journal.ProofSessionSPKI = r.SessionID, fp
			if err := writeArchiveReconfigurationJournal(d.Store, journal); err != nil {
				return rotationRefused()
			}
		}
		return proto.BaseResponse{Success: true, Data: proto.ArchiveSessionKeySignature{Signature: signed.Data.(proto.SignRequestResponseData).Signature}}
	})
}
