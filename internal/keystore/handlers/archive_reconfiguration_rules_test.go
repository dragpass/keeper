package handlers

import (
	"errors"
	"strings"
	"testing"

	"github.com/dragpass/keeper/config"
	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// Each test below pins one rule of the rotation, supplement and finalize
// handlers that no other test detects when the rule is removed.

// Shares that reconstruct a key other than the split's source archive key
// return nothing, even with no grant to unwrap.
func TestRotationRefusesSharesOfAnotherSourceKey(t *testing.T) {
	c := newSupplementCase(t)
	other, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	rot := newRotationRun(t, c.f, c.split, other.PrivateKey)
	if r := rot.run(rot.decision(t)); r.Success || r.Data != nil {
		t.Fatal("rotated with shares of another key")
	}
}

// A reconfiguration closed or finalized while the rewrap ran returns no
// ciphertext, although the session slot is unchanged.
func TestRotationRechecksTargetBeforeOutput(t *testing.T) {
	c := newSupplementCase(t)
	rot := newRotationRun(t, c.f, c.split, c.f.archiveSourcePEM(t, c.split.OrgID))
	d := rot.decision(t)
	lock := archiveSlotProcessLock
	t.Cleanup(func() { archiveSlotProcessLock = lock })
	calls := 0
	archiveSlotProcessLock = func(s keychain.SecretStore, fn func() error) error {
		calls++
		if calls == 2 {
			stage, err := readStageJournal(c.f.store, c.split.OrgID)
			if err != nil {
				t.Fatal(err)
			}
			stage.Finalization = "recorded"
			if err := writeArchiveReconfigurationJournal(c.f.store, stage); err != nil {
				t.Fatal(err)
			}
		}
		return lock(s, fn)
	}
	if r := rot.run(d); r.Success || r.Data != nil {
		t.Fatal("output released after the reconfiguration changed")
	}
}

// Rotation prepare refuses a device other than the one that staged the key.
func TestRotationPrepareRequiresStagingDevice(t *testing.T) {
	c := newSupplementCase(t)
	rot := newRotationRun(t, c.f, c.split, c.f.archiveSourcePEM(t, c.split.OrgID))
	if err := c.f.store.Set(config.Service, config.DeviceID, splitTestOther); err != nil {
		t.Fatal(err)
	}
	if r := HandleArchiveRotationPrepare(c.f.deps, proto.ArchiveRotationPrepare{Request: rot.req, TokenID: splitTestToken, SessionStart: 123}); r.Success {
		t.Fatal("prepared rotation on another device")
	}
}

// A decision naming another device is refused. The challenge context binds
// the same device, so this rule duplicates it; it stays as a direct check.
func TestRotationRefusesDecisionForAnotherDevice(t *testing.T) {
	c := newSupplementCase(t)
	rot := newRotationRun(t, c.f, c.split, c.f.archiveSourcePEM(t, c.split.OrgID))
	d := rot.decision(t)
	d.DeviceID = splitTestOther
	d.Signature = c.f.sign(t, d.Canonical())
	if r := rot.run(d); r.Success || r.Data != nil {
		t.Fatal("decision for another device accepted")
	}
}

// Supplement prepare checks the live slot's owner: after a new login of the
// same account the candidate is not created.
func TestSupplementPrepareRequiresSessionOwner(t *testing.T) {
	c := newSupplementCase(t)
	setSlotTestOwner(t, c.f.deps, c.f.v.AccountID)
	if r := c.prepare(); r.Success || r.ErrorCode != string(errs.ErrCodeArchiveSessionLoginUnavailable) {
		t.Fatal("candidate prepared for another login:", r.ErrorCode)
	}
	if _, err := c.candidatePrivate(); !errors.Is(err, keychain.ErrSecretNotFound) {
		t.Fatal("candidate written")
	}
}

// The session key proof refuses a slot whose private key does not match its
// public half, even when the request names the private key's own SPKI.
func TestSessionKeyProofRequiresMatchingPrivateKey(t *testing.T) {
	f := newSplitFixture(t)
	split, _ := f.authorizeReconfiguration(t)
	if r := HandleArchiveKeySplit(f.deps, split); !r.Success {
		t.Fatal(r.ErrorCode)
	}
	beginOrgSession(t, f.deps, split.OrgID)
	if r := HandleRequestKeyGenerate(f.deps, proto.RequestKeyGenerateRequest{}); !r.Success {
		t.Fatal(r.ErrorCode)
	}
	slot, err := inspectArchiveSessionSlotLocked(f.deps, split.OrgID, nil)
	if err != nil {
		t.Fatal(err)
	}
	other, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	record := encodeArchiveSessionSlot(slot.record, []byte(other.PrivateKey))
	defer record.Destroy()
	if err := keychain.SaveArchiveSessionPrivateKey(f.store, split.OrgID, string(record.Bytes())); err != nil {
		t.Fatal(err)
	}
	otherSPKI, err := crypto.RewrapKeyFingerprint(other.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	r := HandleArchiveReconfigurationSessionKeyProof(f.deps, proto.ArchiveReconfigurationSessionKeyProof{OrgID: split.OrgID, OperationID: split.OperationID, ConfigDigest: split.ConfigDigest, SessionID: splitTestOther, SessionSPKI: otherSPKI})
	if r.Success || r.Data != nil {
		t.Fatal("signed a proof for a mismatched private key")
	}
}

// A candidate whose record names another owner is neither returned nor
// promoted.
func TestSupplementCandidateOwnerIsChecked(t *testing.T) {
	c := newSupplementCase(t)
	res := c.prepare()
	if !res.Success {
		t.Fatal(res.ErrorCode)
	}
	raw, err := c.candidatePrivate()
	if err != nil {
		t.Fatal(err)
	}
	rec, pem, ok := decodeArchiveSessionSlot(raw)
	if !ok {
		t.Fatal("candidate record unreadable")
	}
	rec.owner.account = splitTestOther
	record := encodeArchiveSessionSlot(rec, []byte(pem))
	defer record.Destroy()
	if err := keychain.SaveArchiveSessionPrivateKey(c.f.store, supplementSlot(c.split.OrgID), string(record.Bytes())); err != nil {
		t.Fatal(err)
	}
	if r := c.prepare(); r.Success {
		t.Fatal("returned a candidate of another owner")
	}
	before, _ := keychain.GetArchiveSessionPublicKey(c.f.store, c.split.OrgID)
	if r := c.promote(c.receipt(t, res.Data.(proto.SupplementCandidate))); r.Success {
		t.Fatal("promoted a candidate of another owner")
	}
	if after, _ := keychain.GetArchiveSessionPublicKey(c.f.store, c.split.OrgID); after != before {
		t.Fatal("refused promotion changed the session slot")
	}
}

// A begin that replaced the source session after prepare is never
// overwritten by a promotion.
func TestSupplementPromoteNeverOverwritesALaterBegin(t *testing.T) {
	c := newSupplementCase(t)
	res := c.prepare()
	if !res.Success {
		t.Fatal(res.ErrorCode)
	}
	if r := HandleArchiveSessionEnd(c.f.deps, proto.ArchiveSessionEndRequest{OrgID: c.split.OrgID, Fingerprint: c.prior.Fingerprint}); !r.Success {
		t.Fatal(r.ErrorCode)
	}
	later := beginOrgSession(t, c.f.deps, c.split.OrgID)
	if r := c.promote(c.receipt(t, res.Data.(proto.SupplementCandidate))); r.Success {
		t.Fatal("promotion replaced a later begin")
	}
	slot, err := inspectArchiveSessionSlotLocked(c.f.deps, c.split.OrgID, nil)
	if err != nil || slot.state != archiveSessionSlotLive || slot.publicKey != later.SessionPublicKey || slot.record.fingerprint != later.Fingerprint {
		t.Fatal("later session key changed")
	}
}

// partialPromotion leaves the candidate private half in the session slot
// beside the prior public half, as a crash between the two writes does.
func (c *supplementCase) partialPromotion(t *testing.T) proto.SupplementReceipt {
	t.Helper()
	res := c.prepare()
	if !res.Success {
		t.Fatal(res.ErrorCode)
	}
	receipt := c.receipt(t, res.Data.(proto.SupplementCandidate))
	inner := c.f.deps.Store
	c.f.deps.Store = failSupplementWrite{inner, config.OrgArchiveSessionPublicKeyPrefix + c.split.OrgID}
	if r := c.promote(receipt); r.Success {
		t.Fatal("partial promotion reported success")
	}
	c.f.deps.Store = inner
	return receipt
}

// The sweep removes an expired partial promotion only while the public half
// is the prior one the candidate names; an unexplained public half keeps it.
func TestSupplementSweepKeepsPartialPromotionWithUnexplainedPublicHalf(t *testing.T) {
	c := newSupplementCase(t)
	c.partialPromotion(t)
	other, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := keychain.SaveArchiveSessionPublicKey(c.f.store, c.split.OrgID, other.PublicKey); err != nil {
		t.Fatal(err)
	}
	c.f.clock.advance(1900)
	SweepExpiredArchiveSession(c.f.deps)
	if _, err := keychain.GetArchiveSessionPrivateKey(c.f.store, c.split.OrgID); err != nil {
		t.Fatal("sweep deleted a slot with an unexplained public half")
	}
}

// The sweep never deletes an unexpired partial promotion; the same receipt
// then completes it.
func TestSupplementSweepKeepsUnexpiredPartialPromotion(t *testing.T) {
	c := newSupplementCase(t)
	receipt := c.partialPromotion(t)
	SweepExpiredArchiveSession(c.f.deps)
	if _, err := keychain.GetArchiveSessionPrivateKey(c.f.store, c.split.OrgID); err != nil {
		t.Fatal("sweep deleted an unexpired partial promotion")
	}
	if r := c.promote(receipt); !r.Success {
		t.Fatal("promotion could not resume:", r.ErrorCode)
	}
}

// finalizeCase is a split reconfiguration whose active private key is gone,
// ready for archive_split_finalize.
func newFinalizeCase(t *testing.T) *supplementCase {
	t.Helper()
	c := newSupplementCase(t)
	if err := keychain.OrgArchiveActiveSlot(c.split.OrgID).DeletePrivate(c.f.store); err != nil {
		t.Fatal(err)
	}
	return c
}

func (c *supplementCase) refusedFinalizeWritesNothing(t *testing.T, r proto.ArchiveSplitFinalizationReceipt) {
	t.Helper()
	before := c.f.store.(interface{ Snapshot() map[string]string }).Snapshot()
	c.f.resetProbe()
	if res := c.f.finalize(r); res.Success || c.f.probe.sets != 0 || c.f.probe.deletes != 0 {
		t.Fatal("refused finalize changed state", res.ErrorCode)
	}
	after := c.f.store.(interface{ Snapshot() map[string]string }).Snapshot()
	if len(before) != len(after) {
		t.Fatal("refused finalize changed the keychain")
	}
}

// Finalize refuses while the org still holds an active private key, so the
// target public key never stands beside a usable source key.
func TestReconfigurationFinalizeRefusesWithActivePrivateKey(t *testing.T) {
	c := newSupplementCase(t)
	receipt := c.f.finalizationReceipt(t, c.split, c.shares, nil)
	c.refusedFinalizeWritesNothing(t, receipt)
	if err := keychain.OrgArchiveActiveSlot(c.split.OrgID).DeletePrivate(c.f.store); err != nil {
		t.Fatal(err)
	}
	if r := c.f.finalize(receipt); !r.Success {
		t.Fatal("control finalize:", r.ErrorCode)
	}
}

// Finalize binds the committed shares digest.
func TestReconfigurationFinalizeBindsSharesDigest(t *testing.T) {
	c := newFinalizeCase(t)
	c.refusedFinalizeWritesNothing(t, c.f.finalizationReceipt(t, c.split, c.shares, func(r *proto.ArchiveSplitFinalizationReceipt) {
		r.SharesDigest = strings.Repeat("e", 64)
	}))
}

// Finalize acts only for the staging device.
func TestReconfigurationFinalizeRequiresStagingDevice(t *testing.T) {
	c := newFinalizeCase(t)
	if err := c.f.store.Set(config.Service, config.DeviceID, splitTestOther); err != nil {
		t.Fatal(err)
	}
	receipt := c.f.finalizationReceipt(t, c.split, c.shares, nil)
	c.refusedFinalizeWritesNothing(t, receipt)
	if err := c.f.store.Set(config.Service, config.DeviceID, splitTestDevice); err != nil {
		t.Fatal(err)
	}
	if r := c.f.finalize(receipt); !r.Success {
		t.Fatal("control finalize:", r.ErrorCode)
	}
}

// A promotion racing an end and a new begin of the same org leaves exactly
// one usable key: the promoted candidate or the new session, never both and
// never a mix, whichever runs first.
func TestSupplementPromoteRacingABeginKeepsOneKey(t *testing.T) {
	for round := range sessionRaceRounds {
		c := newSupplementCase(t)
		res := c.prepare()
		if !res.Success {
			t.Fatal(res.ErrorCode)
		}
		cand := res.Data.(proto.SupplementCandidate)
		receipt := c.receipt(t, cand)
		var promoted, begun proto.BaseResponse
		raceActors(t,
			func() { promoted = c.promote(receipt) },
			func() {
				HandleArchiveSessionEnd(c.f.deps, proto.ArchiveSessionEndRequest{OrgID: c.split.OrgID, Fingerprint: c.prior.Fingerprint})
				begun = HandleArchiveSessionBegin(c.f.deps, proto.ArchiveSessionBeginRequest{OrgID: c.split.OrgID})
			},
		)
		if promoted.Success == begun.Success {
			t.Fatalf("round %d: promote %v, begin %v", round, promoted.Success, begun.Success)
		}
		want := cand.PublicKey
		if begun.Success {
			want = begun.Data.(proto.ArchiveSessionBeginResponseData).SessionPublicKey
		}
		slot, err := inspectArchiveSessionSlotLocked(c.f.deps, c.split.OrgID, nil)
		if err != nil || slot.state != archiveSessionSlotLive || slot.publicKey != want {
			t.Fatalf("round %d: slot does not hold the winner's key", round)
		}
	}
}
