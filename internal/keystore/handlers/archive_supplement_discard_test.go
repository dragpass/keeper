package handlers

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/dragpass/keeper/config"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

func TestDamagedSupplementDiscard(t *testing.T) {
	c := newSupplementCase(t)
	if !c.prepare().Success {
		t.Fatal("prepare failed")
	}
	d := c.f.deps
	r := proto.SupplementPrepare{SupplementPrevious: c.params}
	slot := supplementSlot(c.split.OrgID)
	raw, err := c.candidatePrivate()
	if err != nil {
		t.Fatal(err)
	}
	live, err := keychain.GetArchiveSessionPrivateKey(d.Store, c.split.OrgID)
	if err != nil {
		t.Fatal(err)
	}
	status := func() proto.SupplementDamage {
		t.Helper()
		res := HandleSupplementDamageStatus(d, r)
		if !res.Success {
			t.Fatal("status refused", res.ErrorCode)
		}
		return res.Data.(proto.SupplementDamage)
	}
	discard := func(s string, confirm bool) bool {
		return HandleSupplementDiscard(d, proto.SupplementDiscard{SupplementPrepare: r, StoredDigest: s, Confirm: confirm}).Success
	}
	if status().StoredDigest != "" {
		t.Fatal("healthy candidate offered for discard")
	}
	if err := keychain.DeleteArchiveSessionPublicKey(d.Store, slot); err != nil {
		t.Fatal(err)
	}
	first := status()
	if first.State != "discardable" || first.StoredDigest == "" {
		t.Fatal("missing confirmation for identified candidate")
	}
	if discard(first.StoredDigest, false) {
		t.Fatal("unconfirmed discard")
	}
	if err := keychain.SaveArchiveSessionPublicKey(d.Store, slot, ""); err != nil {
		t.Fatal(err)
	}
	if discard(first.StoredDigest, true) {
		t.Fatal("accepted stale confirmation after header changed")
	}
	if got, err := c.candidatePrivate(); err != nil || got != raw {
		t.Fatal("modified candidate after refusal")
	}
	next := status()
	if next.StoredDigest == "" || next.StoredDigest == first.StoredDigest {
		t.Fatal("snapshot collision")
	}
	r.OrgID = splitTestOther
	if discard(next.StoredDigest, true) {
		t.Fatal("foreign organization accepted")
	}
	r.SupplementPrevious = c.params
	r.OperationID = splitTestToken
	if discard(next.StoredDigest, true) {
		t.Fatal("foreign operation accepted")
	}
	r.SupplementPrevious = c.params
	if !discard(next.StoredDigest, true) || discard(next.StoredDigest, true) {
		t.Fatal("confirmed discard or replay")
	}
	if _, err := c.candidatePrivate(); !errors.Is(err, keychain.ErrSecretNotFound) {
		t.Fatal("candidate remained")
	}
	if got, err := keychain.GetArchiveSessionPrivateKey(d.Store, c.split.OrgID); err != nil || got != live {
		t.Fatal("live source changed")
	}
	if retry := c.prepare(); !retry.Success {
		t.Fatal("separate prepare after discard", retry.ErrorCode)
	}
	replacement, err := c.candidatePrivate()
	if err != nil || replacement == raw {
		t.Fatal("no fresh candidate")
	}
	if discard(next.StoredDigest, true) {
		t.Fatal("old confirmation discarded the new candidate")
	}
	if got, err := c.candidatePrivate(); err != nil || got != replacement {
		t.Fatal("replacement changed")
	}

}

func TestDamagedSupplementPreservesUnattributedRecord(t *testing.T) {
	c := newSupplementCase(t)
	if !c.prepare().Success {
		t.Fatal("prepare failed")
	}
	slot := supplementSlot(c.split.OrgID)
	r := proto.SupplementPrepare{SupplementPrevious: c.params}
	d := c.f.deps
	if err := keychain.DeleteArchiveSessionPublicKey(d.Store, slot); err != nil {
		t.Fatal(err)
	}
	eligible := HandleSupplementDamageStatus(d, r).Data.(proto.SupplementDamage)
	if err := keychain.SaveArchiveSessionPrivateKey(d.Store, slot, "unattributed"); err != nil {
		t.Fatal(err)
	}
	result := HandleSupplementDamageStatus(d, r)
	if !result.Success || result.Data.(proto.SupplementDamage) != (proto.SupplementDamage{State: "preserved"}) {
		t.Fatal("unattributed candidate disclosed a digest")
	}
	if HandleSupplementDiscard(d, proto.SupplementDiscard{SupplementPrepare: r, StoredDigest: eligible.StoredDigest, Confirm: true}).Success {
		t.Fatal("swapped private record deleted")
	}
	if got, err := c.candidatePrivate(); err != nil || got != "unattributed" {
		t.Fatal("unknown record changed")
	}
}

func TestSupplementDiscardRequiresCurrentLocalBinding(t *testing.T) {
	c := newSupplementCase(t)
	if !c.prepare().Success {
		t.Fatal("prepare failed")
	}
	d := c.f.deps
	r := proto.SupplementPrepare{SupplementPrevious: c.params}
	if err := keychain.DeleteArchiveSessionPublicKey(d.Store, supplementSlot(c.split.OrgID)); err != nil {
		t.Fatal(err)
	}
	status := HandleSupplementDamageStatus(d, r)
	if !status.Success {
		t.Fatal(status.ErrorCode)
	}
	confirmation := proto.SupplementDiscard{SupplementPrepare: r, StoredDigest: status.Data.(proto.SupplementDamage).StoredDigest, Confirm: true}
	raw, err := c.candidatePrivate()
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{splitTestOther, c.f.v.AccountID} {
		setSlotTestOwner(t, d, id)
		if got := HandleSupplementDamageStatus(d, r); got.Success || got.Data != nil {
			t.Fatal("status disclosed after account switch")
		}
		if HandleSupplementDiscard(d, confirmation).Success {
			t.Fatal("confirmed for a different login")
		}
		if got, err := c.candidatePrivate(); err != nil || got != raw {
			t.Fatal("candidate changed after account switch")
		}
	}
}

func TestSupplementDiscardPreservesLegacyAndInterruptedPromotion(t *testing.T) {
	c := newSupplementCase(t)
	prepared := c.prepare()
	if !prepared.Success {
		t.Fatal(prepared.ErrorCode)
	}
	d := c.f.deps
	slot := supplementSlot(c.split.OrgID)
	r := proto.SupplementPrepare{SupplementPrevious: c.params}
	header, err := c.candidateHeader()
	if err != nil {
		t.Fatal(err)
	}
	journal, err := readStageJournal(d.Store, c.split.OrgID)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := c.candidatePrivate()
	if err != nil {
		t.Fatal(err)
	}
	if err = keychain.DeleteArchiveSessionPublicKey(d.Store, slot); err != nil {
		t.Fatal(err)
	}
	status := HandleSupplementDamageStatus(d, r)
	if !status.Success {
		t.Fatal(status.ErrorCode)
	}
	confirm := proto.SupplementDiscard{SupplementPrepare: r, StoredDigest: status.Data.(proto.SupplementDamage).StoredDigest, Confirm: true}
	legacy := journal
	legacy.SupplementBinding = ""
	if err = writeArchiveReconfigurationJournal(d.Store, legacy); err != nil {
		t.Fatal(err)
	}
	if res := HandleSupplementDamageStatus(d, r); !res.Success || res.Data != (proto.SupplementDamage{State: "preserved"}) {
		t.Fatal("offered legacy record")
	}
	if HandleSupplementDiscard(d, confirm).Success {
		t.Fatal("discarded legacy record")
	}
	if err = writeArchiveReconfigurationJournal(d.Store, journal); err != nil {
		t.Fatal(err)
	}
	if err = keychain.SaveArchiveSessionPublicKey(d.Store, slot, header); err != nil {
		t.Fatal(err)
	}
	c.f.deps.Store = failSupplementWrite{d.Store, config.OrgArchiveSessionPublicKeyPrefix + c.split.OrgID}
	if c.promote(c.receipt(t, prepared.Data.(proto.SupplementCandidate))).Success {
		t.Fatal("expected interrupted promotion")
	}
	if err = keychain.DeleteArchiveSessionPublicKey(d.Store, slot); err != nil {
		t.Fatal(err)
	}
	if HandleSupplementDiscard(d, confirm).Success {
		t.Fatal("discarded while promotion was interrupted")
	}
	if got, err := c.candidatePrivate(); err != nil || got != raw {
		t.Fatal("candidate changed")
	}
}

func TestSweepKeepsSupplementWithMissingOperation(t *testing.T) {
	c := newSupplementCase(t)
	if !c.prepare().Success {
		t.Fatal("prepare failed")
	}
	header, err := c.candidateHeader()
	if err != nil {
		t.Fatal(err)
	}
	var h supplementCandidate
	if err = json.Unmarshal([]byte(header), &h); err != nil {
		t.Fatal(err)
	}
	h.OperationID = ""
	damaged, err := json.Marshal(h)
	if err != nil {
		t.Fatal(err)
	}
	if err = keychain.SaveArchiveSessionPublicKey(c.f.store, supplementSlot(c.split.OrgID), string(damaged)); err != nil {
		t.Fatal(err)
	}
	raw, err := c.candidatePrivate()
	if err != nil {
		t.Fatal(err)
	}
	c.f.clock.advance(1900)
	SweepExpiredArchiveSession(c.f.deps)
	if got, err := c.candidatePrivate(); err != nil || got != raw {
		t.Fatal("sweep deleted an unidentifiable supplementary candidate")
	}
}
