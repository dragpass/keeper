package handlers

import (
	"errors"
	"github.com/dragpass/keeper/config"
	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
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
