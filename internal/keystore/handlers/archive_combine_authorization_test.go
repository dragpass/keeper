package handlers

import (
	"bytes"
	"encoding/base64"
	"github.com/dragpass/keeper/config"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"reflect"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/testdouble"
)

func TestArchiveCombineMissingAuthorityHasNoEffects(t *testing.T) {
	f := newAuditFixture(t)
	target, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	req := proto.ArchiveQuorumCombineAndRewrapRequest{
		OwnerAccountID: f.v.AccountID, GrantContext: legacyContext(f.v),
		WrappedOldDEKB64: f.wrapToMe(t, f.pubPEM, legacyContext(f.v)),
		RewrappedShares:  []proto.RewrappedShareInput{{WrappedKey: "AA==", Ciphertext: "AA=="}, {WrappedKey: "AQ==", Ciphertext: "AQ=="}},
		Recipients:       []proto.DEKRewrapRecipient{{AccountID: "77777777-7777-4777-8777-777777777777", PublicKey: target.PublicKey}},
	}
	before := f.store.(*testdouble.MemorySecretStore).Snapshot()
	response := HandleArchiveQuorumCombineAndRewrap(f.deps, req)
	if !reflect.DeepEqual(before, f.store.(*testdouble.MemorySecretStore).Snapshot()) {
		t.Fatal("unsigned combine changed keychain state before authority verification")
	}
	if response.Success || response.Data != nil || response.ErrorCode != "not_found" {
		t.Fatal("unsigned combine was not refused at authority boundary")
	}
}

func authorizedCombineFixture(t *testing.T) (*auditFixture, proto.ArchiveQuorumCombineAndRewrapRequest) {
	t.Helper()
	f := newAuditFixture(t)
	f.deps.GroupRewrapChallenges = NewGroupRewrapChallengeStore()
	device := "55555555-5555-4555-8555-555555555555"
	if err := f.store.Set(config.Service, config.DeviceID, device); err != nil {
		t.Fatal(err)
	}
	archive, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	shares, err := crypto.SplitSecret([]byte(archive.PrivateKey), 2, 2)
	if err != nil {
		t.Fatal(err)
	}
	session := HandleArchiveSessionBegin(f.deps, proto.ArchiveSessionBeginRequest{})
	if !session.Success {
		t.Fatal("session setup failed")
	}
	pub, err := crypto.ParsePublicKey(session.Data.(proto.ArchiveSessionBeginResponseData).SessionPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	req := proto.ArchiveQuorumCombineAndRewrapRequest{
		RecoverySessionID: "99999999-9999-4999-8999-999999999999",
		OwnerAccountID:    f.v.AccountID, GrantContext: legacyContext(f.v),
		WrappedOldDEKB64: f.wrapToMe(t, archive.PublicKey, legacyContext(f.v)),
		Recipients:       []proto.DEKRewrapRecipient{{AccountID: "77777777-7777-4777-8777-777777777777", PublicKey: f.pubPEM}},
	}
	for _, share := range shares {
		raw := crypto.SerializeShare(share)
		wk, ct, err := crypto.HybridWrap(pub, raw)
		if err != nil {
			t.Fatal(err)
		}
		req.RewrappedShares = append(req.RewrappedShares, proto.RewrappedShareInput{WrappedKey: wk, Ciphertext: ct})
	}
	prepared := HandleGroupRewrapPrepare(f.deps, proto.GroupRewrapPrepareRequest{Operation: "quorum_combine", SourceKind: "archive_quorum", TokenID: "66666666-6666-4666-8666-666666666666", SessionIssuedAtNanos: 123, Combine: &req})
	if !prepared.Success {
		t.Fatalf("combine preparation refused: %s", prepared.ErrorCode)
	}
	p := prepared.Data.(proto.GroupRewrapPrepareResponseData)
	decision := proto.GroupRewrapDecision{Challenge: p.Challenge, AccountID: f.v.AccountID, DeviceID: device, TokenID: "66666666-6666-4666-8666-666666666666", SessionIssuedAtNanos: 123, Operation: p.Operation, OrgID: p.OrgID, GroupID: p.GroupID, DEKVersion: p.DEKVersion, SourceKind: p.SourceKind, SourceGrantDigest: p.SourceGrantDigest, SourcePolicy: p.SourcePolicy, OutputPolicy: p.OutputPolicy, RequestDigest: p.RequestDigest, RecipientsDigest: p.RecipientsDigest, IssuedAt: f.clock.now().Unix(), ExpiresAt: f.clock.now().Unix() + 10, ServerKeyVersion: 1}
	decision.Signature = f.sign(t, proto.GroupRewrapDecisionCanonical(decision))
	req.Decision = &decision
	return f, req
}

func TestArchiveCombinePreparedSignedRoundTripAndReplay(t *testing.T) {
	f, req := authorizedCombineFixture(t)
	decision := *req.Decision
	before := f.store.(*testdouble.MemorySecretStore).Snapshot()
	for _, kind := range []string{"session", "share", "recipient", "signature", "operation"} {
		changed := req
		altered := decision
		changed.Decision = &altered
		switch kind {
		case "session":
			changed.RecoverySessionID = "88888888-8888-4888-8888-888888888888"
		case "share":
			changed.RewrappedShares = append([]proto.RewrappedShareInput(nil), req.RewrappedShares...)
			changed.RewrappedShares[1].Ciphertext = "AA=="
		case "recipient":
			changed.Recipients = append([]proto.DEKRewrapRecipient(nil), req.Recipients...)
			changed.Recipients[0].AccountID = "88888888-8888-4888-8888-888888888888"
		case "signature":
			altered.Signature = "AA=="
		case "operation":
			altered.Operation = "rotation_old_grants"
			altered.Signature = f.sign(t, proto.GroupRewrapDecisionCanonical(altered))
		}
		rejected := HandleArchiveQuorumCombineAndRewrap(f.deps, changed)
		if rejected.Success || rejected.Data != nil || !reflect.DeepEqual(before, f.store.(*testdouble.MemorySecretStore).Snapshot()) {
			t.Fatalf("%s mismatch had effects", kind)
		}
	}
	response := HandleArchiveQuorumCombineAndRewrap(f.deps, req)
	if !response.Success {
		t.Fatalf("signed combine refused: %s", response.ErrorCode)
	}
	out := response.Data.(proto.ArchiveQuorumCombineAndRewrapResponseData)
	if len(out.Grants) != 1 {
		t.Fatal("wrong grant count")
	}
	encrypted, err := base64.StdEncoding.DecodeString(out.Grants[0].EncryptedGroupDEKB64)
	if err != nil {
		t.Fatal(err)
	}
	// The fixture uses the same generated DEK for both source wraps.
	source, err := base64.StdEncoding.DecodeString(f.wrapToMe(t, f.pubPEM, legacyContext(f.v)))
	if err != nil {
		t.Fatal(err)
	}
	privBuf, err := GetPrivateKeySecure(f.store)
	if err != nil {
		t.Fatal(err)
	}
	defer privBuf.Destroy()
	priv, err := crypto.ParsePrivateKey(string(privBuf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	actual, err := unwrapGrant(priv, encrypted, legacyContext(f.v))
	if err != nil {
		t.Fatal("result did not open")
	}
	expected, err := unwrapGrant(priv, source, legacyContext(f.v))
	if err != nil || !bytes.Equal(actual, expected) {
		t.Fatal("combined result changed the DEK")
	}
	if replay := HandleArchiveQuorumCombineAndRewrap(f.deps, req); replay.Success || replay.Data != nil {
		t.Fatal("replayed combine returned output")
	}
}

type combinePrivateReadProbe struct {
	keychain.SecretStore
	reads      int
	beforeRead func()
}

func (p *combinePrivateReadProbe) Get(service, account string) (string, error) {
	if account == config.OrgArchiveSessionPrivateKey {
		p.reads++
		if p.beforeRead != nil {
			p.beforeRead()
		}
	}
	return p.SecretStore.Get(service, account)
}

func TestArchiveCombineRefusesStaleAuthorityBeforePrivateRead(t *testing.T) {
	for _, kind := range []string{"expired", "binding", "device", "signature", "login"} {
		t.Run(kind, func(t *testing.T) {
			f, req := authorizedCombineFixture(t)
			probe := &combinePrivateReadProbe{SecretStore: f.store}
			f.deps.Store = probe
			switch kind {
			case "expired":
				f.clock.advance(11)
			case "binding":
				binding, _, err := keychain.GetAccountBinding(f.store)
				if err != nil {
					t.Fatal(err)
				}
				if _, _, err := keychain.SetAccountBinding(f.store, binding.AccountID, binding.Alias, true); err != nil {
					t.Fatal(err)
				}
			case "device":
				if err := f.store.Set(config.Service, config.DeviceID, "88888888-8888-4888-8888-888888888888"); err != nil {
					t.Fatal(err)
				}
			case "signature":
				req.Decision.Signature = "AA=="
			case "login":
				req.Decision.SessionIssuedAtNanos++
				req.Decision.Signature = f.sign(t, proto.GroupRewrapDecisionCanonical(*req.Decision))
			}
			before := f.store.(*testdouble.MemorySecretStore).Snapshot()
			response := HandleArchiveQuorumCombineAndRewrap(f.deps, req)
			if response.Success || response.Data != nil || probe.reads != 0 || !reflect.DeepEqual(before, f.store.(*testdouble.MemorySecretStore).Snapshot()) {
				t.Fatal("stale authority reached private state")
			}
		})
	}
}

func TestArchiveCombineWithholdsOutputIfAuthorityExpiresDuringCrypto(t *testing.T) {
	f, req := authorizedCombineFixture(t)
	probe := &combinePrivateReadProbe{SecretStore: f.store, beforeRead: func() { f.clock.advance(11) }}
	f.deps.Store = probe
	response := HandleArchiveQuorumCombineAndRewrap(f.deps, req)
	if probe.reads != 1 || response.Success || response.Data != nil {
		t.Fatal("expired combine returned output")
	}
}

func TestArchiveCombineSourceBindsStoredSessionAndShares(t *testing.T) {
	_, req := authorizedCombineFixture(t)
	first, _, _, err := combineRewrapCommitments(req)
	if err != nil {
		t.Fatal(err)
	}
	req.RecoverySessionID = "88888888-8888-4888-8888-888888888888"
	changed, _, _, err := combineRewrapCommitments(req)
	if err != nil {
		t.Fatal(err)
	}
	if first.sourceDigest == changed.sourceDigest {
		t.Fatal("source authority does not bind the stored recovery session")
	}
	req.RewrappedShares[0].Ciphertext = "AA=="
	shareChanged, _, _, err := combineRewrapCommitments(req)
	if err != nil {
		t.Fatal(err)
	}
	if changed.sourceDigest == shareChanged.sourceDigest {
		t.Fatal("source authority does not bind the stored approval shares")
	}
}
