package handlers

import (
	"encoding/json"
	"errors"
	"github.com/dragpass/keeper/config"
	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"reflect"
	"testing"
)

type failSupplementWrite struct {
	keychain.SecretStore
	key string
}

func (s failSupplementWrite) Set(service, account, value string) error {
	if account == s.key {
		return errors.New("simulated write failure")
	}
	return s.SecretStore.Set(service, account, value)
}

func TestSupplementPreservesOriginalUntilSignedAcceptance(t *testing.T) {
	f := newSplitFixture(t)
	split, _ := f.authorizeReconfiguration(t)
	if r := HandleArchiveKeySplit(f.deps, split); !r.Success {
		t.Fatal(r.ErrorCode)
	}
	prior := beginOrgSession(t, f.deps, split.OrgID)
	prev, _ := crypto.RewrapKeyFingerprint(prior.SessionPublicKey)
	if r := HandleRequestKeyGenerate(f.deps, proto.RequestKeyGenerateRequest{}); !r.Success {
		t.Fatal(r.ErrorCode)
	}
	if r := HandleArchiveReconfigurationSessionKeyProof(f.deps, proto.ArchiveReconfigurationSessionKeyProof{OrgID: split.OrgID, OperationID: split.OperationID, ConfigDigest: split.ConfigDigest, SessionID: splitTestOther, SessionSPKI: prev}); !r.Success {
		t.Fatal(r.ErrorCode)
	}
	params := proto.SupplementPrevious{OrgID: split.OrgID, OperationID: split.OperationID, ConfigDigest: split.ConfigDigest, PreviousSessionID: splitTestOther, PreviousSPKI: prev}
	prepare := func() proto.BaseResponse {
		return HandleSupplementPrepare(f.deps, proto.SupplementPrepare{SupplementPrevious: params})
	}
	res := prepare()
	if !res.Success {
		t.Fatal(res.ErrorCode)
	}
	cand := res.Data.(proto.SupplementCandidate)
	if cand.SPKI == prev || cand.PublicKey == prior.SessionPublicKey || prepare().Data != cand {
		t.Fatal("retry changed candidate")
	}
	receipt := proto.SupplementReceipt{SupplementPrevious: params, AccountID: f.v.AccountID, DeviceID: splitTestDevice, SessionID: splitTestToken, SPKI: cand.SPKI, Round: 1, ExpiresAt: f.deps.Now().Unix() + 80, Version: 1, Signature: "invalid"}
	promote := func() proto.BaseResponse {
		return HandleSupplementPromote(f.deps, proto.SupplementPromote{Receipt: receipt})
	}
	if promote().Success {
		t.Fatal("accepted invalid signature")
	}
	original, err := keychain.GetArchiveSessionPublicKey(f.store, split.OrgID)
	if err != nil || original != prior.SessionPublicKey {
		t.Fatal("original key changed before acceptance")
	}
	for _, mutate := range []func(*proto.SupplementReceipt){
		func(r *proto.SupplementReceipt) { r.Round++ },
		func(r *proto.SupplementReceipt) { r.PreviousSessionID = splitTestOperation },
		func(r *proto.SupplementReceipt) { r.ExpiresAt = f.deps.Now().Unix() },
		func(r *proto.SupplementReceipt) { r.DeviceID = splitTestOther },
	} {
		wrong := receipt
		mutate(&wrong)
		wrong.Signature = f.sign(t, wrong.Canonical())
		if r := HandleSupplementPromote(f.deps, proto.SupplementPromote{Receipt: wrong}); r.Success {
			t.Fatal("incompatible acceptance promoted")
		}
	}
	receipt.Signature = f.sign(t, receipt.Canonical())
	originalStore := f.deps.Store
	f.deps.Store = failSupplementWrite{originalStore, config.OrgArchiveSessionPublicKeyPrefix + split.OrgID}
	if promote().Success {
		t.Fatal("partial promotion reported as complete")
	}
	f.deps.Store = originalStore
	if r := promote(); !r.Success {
		t.Fatal(r.ErrorCode)
	}
	if r := promote(); !r.Success {
		t.Fatal("receipt replay", r.ErrorCode)
	}
	slot, err := inspectArchiveSessionSlotLocked(f.deps, split.OrgID, nil)
	if err != nil || slot.publicKey != cand.PublicKey || slot.state != archiveSessionSlotLive || slot.record.expiresAt.Unix() != receipt.ExpiresAt {
		t.Fatal("promotion did not install accepted candidate")
	}
	params.PreviousSessionID, params.PreviousSPKI = receipt.SessionID, cand.SPKI
	next := HandleSupplementPrepare(f.deps, proto.SupplementPrepare{SupplementPrevious: params, PreviousRound: 1})
	if !next.Success {
		t.Fatal("second round candidate", next.ErrorCode)
	}
	if !promote().Success {
		t.Fatal("receipt retry disturbed next candidate")
	}
	nextAgain := HandleSupplementPrepare(f.deps, proto.SupplementPrepare{SupplementPrevious: params, PreviousRound: 1})
	if !nextAgain.Success || nextAgain.Data != next.Data {
		t.Fatal("next candidate changed on earlier acceptance retry")
	}
	second := proto.SupplementReceipt{SupplementPrevious: params, AccountID: receipt.AccountID, DeviceID: receipt.DeviceID, SessionID: splitTestOperation, SPKI: next.Data.(proto.SupplementCandidate).SPKI, Round: 2, ExpiresAt: f.deps.Now().Unix() + 60, Version: 1}
	second.Signature = f.sign(t, second.Canonical())
	f.deps.Store = failSupplementWrite{originalStore, config.OrgArchiveSessionPublicKeyPrefix + split.OrgID}
	if HandleSupplementPromote(f.deps, proto.SupplementPromote{Receipt: second}).Success {
		t.Fatal("partial second promotion reported success")
	}
	f.deps.Store = originalStore
	f.clock.advance(1900)
	SweepExpiredArchiveSession(f.deps)
	if _, err := keychain.GetArchiveSessionPrivateKey(f.store, supplementSlot(split.OrgID)); !errors.Is(err, keychain.ErrSecretNotFound) {
		t.Fatal("expired candidate survived sweep")
	}
	if _, err := keychain.GetArchiveSessionPrivateKey(f.store, split.OrgID); !errors.Is(err, keychain.ErrSecretNotFound) {
		t.Fatal("expired partial promotion survived sweep")
	}
}

// supplementCase is a split reconfiguration with a live proven source
// session, ready for supplement_prepare.
type supplementCase struct {
	f      *splitFixture
	split  proto.ArchiveKeySplitRequest
	shares []proto.WrappedShare
	prior  proto.ArchiveSessionBeginResponseData
	params proto.SupplementPrevious
}

func newSupplementCase(t *testing.T) *supplementCase {
	t.Helper()
	f := newSplitFixture(t)
	f.deps.ArchiveRotationChallenges = NewArchiveShareChallengeStore()
	split, _ := f.authorizeReconfiguration(t)
	res := HandleArchiveKeySplit(f.deps, split)
	if !res.Success {
		t.Fatal(res.ErrorCode)
	}
	// The App begins a reconfiguration session with the operation ID.
	begun := HandleArchiveSessionBegin(f.deps, proto.ArchiveSessionBeginRequest{OrgID: split.OrgID, BeginID: split.OperationID})
	if !begun.Success {
		t.Fatal(begun.ErrorCode)
	}
	prior := begun.Data.(proto.ArchiveSessionBeginResponseData)
	prev, _ := crypto.RewrapKeyFingerprint(prior.SessionPublicKey)
	if r := HandleRequestKeyGenerate(f.deps, proto.RequestKeyGenerateRequest{}); !r.Success {
		t.Fatal(r.ErrorCode)
	}
	if r := HandleArchiveReconfigurationSessionKeyProof(f.deps, proto.ArchiveReconfigurationSessionKeyProof{OrgID: split.OrgID, OperationID: split.OperationID, ConfigDigest: split.ConfigDigest, SessionID: splitTestOther, SessionSPKI: prev}); !r.Success {
		t.Fatal(r.ErrorCode)
	}
	return &supplementCase{f: f, split: split, shares: res.Data.(proto.ArchiveKeySplitResponseData).Shares, prior: prior,
		params: proto.SupplementPrevious{OrgID: split.OrgID, OperationID: split.OperationID, ConfigDigest: split.ConfigDigest, PreviousSessionID: splitTestOther, PreviousSPKI: prev}}
}

func (c *supplementCase) prepare() proto.BaseResponse {
	return HandleSupplementPrepare(c.f.deps, proto.SupplementPrepare{SupplementPrevious: c.params})
}

// receipt is a signed acceptance of cand for the first supplementary round.
func (c *supplementCase) receipt(t *testing.T, cand proto.SupplementCandidate) proto.SupplementReceipt {
	t.Helper()
	r := proto.SupplementReceipt{SupplementPrevious: c.params, AccountID: c.f.v.AccountID, DeviceID: splitTestDevice, SessionID: splitTestToken, SPKI: cand.SPKI, Round: 1, ExpiresAt: c.f.deps.Now().Unix() + 600, Version: 1}
	r.Signature = c.f.sign(t, r.Canonical())
	return r
}

func (c *supplementCase) promote(r proto.SupplementReceipt) proto.BaseResponse {
	return HandleSupplementPromote(c.f.deps, proto.SupplementPromote{Receipt: r})
}

func (c *supplementCase) candidatePrivate() (string, error) {
	return keychain.GetArchiveSessionPrivateKey(c.f.store, supplementSlot(c.split.OrgID))
}

func (c *supplementCase) candidateHeader() (string, error) {
	return keychain.GetArchiveSessionPublicKey(c.f.store, supplementSlot(c.split.OrgID))
}

// An interrupted candidate write leaves no private key, only the header; a
// retry stores a complete candidate and the sweep removes a lone header.
func TestSupplementInterruptedWriteLeavesNoPrivateKey(t *testing.T) {
	c := newSupplementCase(t)
	inner := c.f.deps.Store
	c.f.deps.Store = failSupplementWrite{inner, config.OrgArchiveSessionPrivateKeyPrefix + supplementSlot(c.split.OrgID)}
	if r := c.prepare(); r.Success || r.ErrorCode != string(errs.ErrCodeStorageFailure) {
		t.Fatal("interrupted candidate write:", r.ErrorCode)
	}
	c.f.deps.Store = inner
	if _, err := c.candidatePrivate(); !errors.Is(err, keychain.ErrSecretNotFound) {
		t.Fatal("private candidate written after failure")
	}
	if _, err := c.candidateHeader(); err != nil {
		t.Fatal("header was not written first")
	}
	SweepExpiredArchiveSession(c.f.deps)
	if _, err := c.candidateHeader(); !errors.Is(err, keychain.ErrSecretNotFound) {
		t.Fatal("lone header survived the sweep")
	}
	first := c.prepare()
	if !first.Success {
		t.Fatal(first.ErrorCode)
	}
	if again := c.prepare(); !again.Success || again.Data != first.Data {
		t.Fatal("retry did not return the stored candidate")
	}
}

// A failed candidate delete is reported and leaves the complete candidate,
// which the same receipt then removes.
func TestSupplementCandidateDeleteIsAllOrReported(t *testing.T) {
	c := newSupplementCase(t)
	res := c.prepare()
	if !res.Success {
		t.Fatal(res.ErrorCode)
	}
	cand := res.Data.(proto.SupplementCandidate)
	receipt := c.receipt(t, cand)
	c.f.probe.deleteHook = func(account string) error {
		if account == config.OrgArchiveSessionPrivateKeyPrefix+supplementSlot(c.split.OrgID) {
			return errors.New("simulated delete failure")
		}
		return nil
	}
	if r := c.promote(receipt); r.Success || r.ErrorCode != string(errs.ErrCodeStorageFailure) {
		t.Fatal("failed candidate delete:", r.ErrorCode)
	}
	if _, err := c.candidatePrivate(); err != nil {
		t.Fatal("candidate private half lost")
	}
	if _, err := c.candidateHeader(); err != nil {
		t.Fatal("header deleted before the private half")
	}
	c.f.probe.deleteHook = nil
	if r := c.promote(receipt); !r.Success {
		t.Fatal(r.ErrorCode)
	}
	if _, err := c.candidatePrivate(); !errors.Is(err, keychain.ErrSecretNotFound) {
		t.Fatal("candidate survived the completed promotion")
	}
	if _, err := c.candidateHeader(); !errors.Is(err, keychain.ErrSecretNotFound) {
		t.Fatal("header survived the completed promotion")
	}
}

// candidateItems is one prepared candidate's two keychain values.
type candidateItems struct{ header, private, public string }

// twoCandidates prepares a candidate, removes it and prepares another, and
// returns both candidates' items. The second stays stored.
func (c *supplementCase) twoCandidates(t *testing.T) (candidateItems, candidateItems) {
	t.Helper()
	take := func() candidateItems {
		res := c.prepare()
		if !res.Success {
			t.Fatal(res.ErrorCode)
		}
		header, err1 := c.candidateHeader()
		private, err2 := c.candidatePrivate()
		if err1 != nil || err2 != nil {
			t.Fatal("candidate items missing")
		}
		return candidateItems{header, private, res.Data.(proto.SupplementCandidate).PublicKey}
	}
	a := take()
	for _, del := range []func(keychain.SecretStore, string) error{keychain.DeleteArchiveSessionPrivateKey, keychain.DeleteArchiveSessionPublicKey} {
		if err := del(c.f.store, supplementSlot(c.split.OrgID)); err != nil {
			t.Fatal(err)
		}
	}
	return a, take()
}

// recordWithFingerprint re-encodes the private record of items with the
// given fingerprint field.
func recordWithFingerprint(t *testing.T, items candidateItems, fingerprint string) string {
	t.Helper()
	rec, pem, ok := decodeArchiveSessionSlot(items.private)
	if !ok {
		t.Fatal("candidate record unreadable")
	}
	rec.fingerprint = fingerprint
	record := encodeArchiveSessionSlot(rec, []byte(pem))
	defer record.Destroy()
	return string(record.Bytes())
}

// A header and a private half that do not belong together are never
// returned, promoted or swept: prepare and promote refuse with not_found,
// nothing is written and the live session key is untouched.
func TestSupplementMixedCandidateHalvesFailClosed(t *testing.T) {
	cases := map[string]func(t *testing.T, a, b candidateItems) (header, private string){
		"items of two prepares": func(t *testing.T, a, b candidateItems) (string, string) {
			return a.header, b.private
		},
		"record claims the header key": func(t *testing.T, a, b candidateItems) (string, string) {
			return a.header, recordWithFingerprint(t, b, fingerprintBase64Public(a.public))
		},
		"record fingerprint altered": func(t *testing.T, a, b candidateItems) (string, string) {
			return b.header, recordWithFingerprint(t, b, fingerprintBase64Public(a.public))
		},
	}
	for name, mix := range cases {
		t.Run(name, func(t *testing.T) {
			c := newSupplementCase(t)
			a, b := c.twoCandidates(t)
			header, private := mix(t, a, b)
			if err := keychain.SaveArchiveSessionPublicKey(c.f.store, supplementSlot(c.split.OrgID), header); err != nil {
				t.Fatal(err)
			}
			if err := keychain.SaveArchiveSessionPrivateKey(c.f.store, supplementSlot(c.split.OrgID), private); err != nil {
				t.Fatal(err)
			}
			var stored supplementCandidate
			if err := json.Unmarshal([]byte(header), &stored); err != nil {
				t.Fatal(err)
			}
			livePrivate, _ := keychain.GetArchiveSessionPrivateKey(c.f.store, c.split.OrgID)
			livePublic, _ := keychain.GetArchiveSessionPublicKey(c.f.store, c.split.OrgID)
			c.f.resetProbe()
			if r := c.prepare(); r.Success || r.ErrorCode != string(errs.ErrCodeNotFound) {
				t.Fatal("prepare answered a mixed candidate:", r.ErrorCode)
			}
			if r := c.promote(c.receipt(t, stored.SupplementCandidate)); r.Success || r.ErrorCode != string(errs.ErrCodeNotFound) {
				t.Fatal("promote accepted a mixed candidate:", r.ErrorCode)
			}
			if c.f.probe.sets != 0 || c.f.probe.deletes != 0 {
				t.Fatal("refusal wrote or deleted state")
			}
			gotPrivate, _ := keychain.GetArchiveSessionPrivateKey(c.f.store, c.split.OrgID)
			gotPublic, _ := keychain.GetArchiveSessionPublicKey(c.f.store, c.split.OrgID)
			if gotPrivate != livePrivate || gotPublic != livePublic {
				t.Fatal("live session key changed")
			}
			c.f.clock.advance(1900)
			SweepExpiredArchiveSession(c.f.deps)
			if got, err := c.candidatePrivate(); err != nil || got != private {
				t.Fatal("sweep removed an unidentifiable candidate")
			}
			if got, err := c.candidateHeader(); err != nil || got != header {
				t.Fatal("sweep removed the header of an unidentifiable candidate")
			}
		})
	}
}

// A promoted session record carries no begin ID: a begin naming the
// previous session, the original begin ID or none is refused as
// archive_session_active, writes nothing and leaves the promoted key, its
// status and its expiry handling as they were.
func TestSupplementPromotedRecordReplaysNoBegin(t *testing.T) {
	c := newSupplementCase(t)
	res := c.prepare()
	if !res.Success {
		t.Fatal(res.ErrorCode)
	}
	cand := res.Data.(proto.SupplementCandidate)
	if r := c.promote(c.receipt(t, cand)); !r.Success {
		t.Fatal(r.ErrorCode)
	}
	status := func() proto.BaseResponse {
		return HandleArchiveSessionStatus(c.f.deps, proto.ArchiveSessionStatusRequest{OrgID: c.split.OrgID})
	}
	before := status()
	if !before.Success {
		t.Fatal(before.ErrorCode)
	}
	for _, beginID := range []string{c.params.PreviousSessionID, c.split.OperationID, ""} {
		c.f.resetProbe()
		r := HandleArchiveSessionBegin(c.f.deps, proto.ArchiveSessionBeginRequest{OrgID: c.split.OrgID, BeginID: beginID})
		if r.Success || r.ErrorCode != string(errs.ErrCodeArchiveSessionActive) || c.f.probe.sets != 0 || c.f.probe.deletes != 0 {
			t.Fatalf("begin %q after promotion: %s", beginID, r.ErrorCode)
		}
		if public, _ := keychain.GetArchiveSessionPublicKey(c.f.store, c.split.OrgID); public != cand.PublicKey {
			t.Fatalf("begin %q changed the promoted key", beginID)
		}
	}
	if after := status(); !reflect.DeepEqual(after, before) {
		t.Fatal("status of the promoted record changed")
	}
	c.f.clock.advance(601)
	SweepExpiredArchiveSession(c.f.deps)
	if _, err := keychain.GetArchiveSessionPrivateKey(c.f.store, c.split.OrgID); !errors.Is(err, keychain.ErrSecretNotFound) {
		t.Fatal("expired promoted record survived the sweep")
	}
}
