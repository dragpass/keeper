package handlers

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/dragpass/keeper/config"
	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/keytransparency"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"strings"
	"testing"
)

func TestArchiveShareRewrapRefusesMissingDecision(t *testing.T) {
	d, _, store := newTestDeps(t)
	owner, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	target, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := keychain.SaveAccountArchivePrivateKey(store, owner.PrivateKey); err != nil {
		t.Fatal(err)
	}
	pub, err := crypto.ParsePublicKey(owner.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	wk, ct, err := crypto.HybridWrap(pub, []byte("test share"))
	if err != nil {
		t.Fatal(err)
	}
	r := HandleArchiveShareRewrap(d, proto.ArchiveShareRewrapRequest{WrappedKey: wk, Ciphertext: ct, SessionPublicKey: target.PublicKey})
	if r.Success || r.Data != nil {
		t.Fatal("share was rewrapped without online authority")
	}
}

func authorizedArchiveShareFixture(t *testing.T) (*auditFixture, proto.ArchiveShareRewrapRequest, string) {
	t.Helper()
	return archiveShareFixture(t, archiveShareFixtureOptions{})
}

type archiveShareFixtureOptions struct {
	self            bool
	operationID     string
	signedSession   string
	sourceRound     int
	signedRound     *int
	signedOperation string
	signedConfig    string
	materialProof   bool
	alterProof      func(*archiveRequesterProof)
}

func archiveShareFixture(t *testing.T, opt archiveShareFixtureOptions) (*auditFixture, proto.ArchiveShareRewrapRequest, string) {
	t.Helper()
	f := newAuditFixture(t)
	f.deps.ArchiveShareChallenges = NewArchiveShareChallengeStore()
	device := "55555555-5555-4555-8555-555555555555"
	if err := f.store.Set(config.Service, config.DeviceID, device); err != nil {
		t.Fatal(err)
	}
	owner, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	target, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := keychain.SaveAccountArchivePrivateKey(f.store, owner.PrivateKey); err != nil {
		t.Fatal(err)
	}
	pub, err := crypto.ParsePublicKey(owner.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	wk, ct, err := crypto.HybridWrap(pub, []byte("test share"))
	if err != nil {
		t.Fatal(err)
	}
	req := proto.ArchiveShareRewrapRequest{AccountID: f.v.AccountID, OrgID: f.v.OrgID, RecoverySessionID: "77777777-7777-4777-8777-777777777777", WrappedKey: wk, Ciphertext: ct, SessionPublicKey: target.PublicKey}
	operationID := opt.operationID
	req.SplitOperationID = operationID
	requester := pinPeer
	if opt.self {
		requester = req.AccountID
	}
	purpose := "reconfiguration"
	if operationID == "" {
		purpose = "recovery"
		req.RecoveryTarget = &proto.ArchiveRecoveryTarget{RequesterAccountID: requester, GroupID: sessionTestGroup, DekVersion: 3}
	} else {
		req.SourceTarget = &proto.ArchiveSourceTarget{RequesterAccountID: requester, ConfigDigest: strings.Repeat("a", 64), SessionRound: &opt.sourceRound}
	}
	attachment := signedRequesterAttachment(t, f, req, pub, opt)
	prepare := proto.ArchiveSharePrepareRequest{Request: req, TokenID: "66666666-6666-4666-8666-666666666666", SessionIssuedAtNanos: 123}
	response := HandleArchiveSharePrepare(f.deps, prepare)
	if !response.Success {
		t.Fatal("valid preparation refused")
	}
	prepared := response.Data.(proto.ArchiveSharePrepareResponseData)
	if prepared.PreviousTreeSize == nil {
		t.Fatal("wrong proof anchor response")
	}
	decision := proto.ArchiveShareDecision{Purpose: purpose, SplitOperationID: operationID, RequesterProof: attachment, Challenge: prepared.Challenge, AccountID: req.AccountID, DeviceID: device, TokenID: prepare.TokenID, SessionIssuedAtNanos: 123, OrgID: req.OrgID, RecoverySessionID: req.RecoverySessionID, QuorumID: "88888888-8888-4888-8888-888888888888", RequestDigest: prepared.RequestDigest, IssuedAt: f.clock.now().Unix(), ExpiresAt: f.clock.now().Unix() + 10, ServerKeyVersion: 1}
	decision.Signature = f.sign(t, proto.ArchiveShareDecisionCanonical(decision))
	req.Decision = &decision
	return f, req, target.PrivateKey
}

func TestArchiveShareAuthorizedRoundTripAndReplay(t *testing.T) {
	f, req, privateKey := authorizedArchiveShareFixture(t)
	response := HandleArchiveShareRewrap(f.deps, req)
	if !response.Success {
		t.Fatal("valid authorized execution refused")
	}
	out := response.Data.(proto.ArchiveShareRewrapResponseData)
	priv, err := crypto.ParsePrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := crypto.HybridUnwrap(priv, out.WrappedKey, out.Ciphertext)
	if err != nil || string(opened) != "test share" {
		t.Fatal("authorized share did not round trip")
	}
	if replay := HandleArchiveShareRewrap(f.deps, req); replay.Success || replay.Data != nil {
		t.Fatal("decision replay returned output")
	}
}

type archivePrivateReadProbe struct {
	keychain.SecretStore
	reads      int
	beforeRead func()
}

func (s *archivePrivateReadProbe) Get(service, account string) (string, error) {
	if account == config.AccountArchivePrivateKey {
		s.reads++
		if s.beforeRead != nil {
			s.beforeRead()
		}
	}
	return s.SecretStore.Get(service, account)
}
func TestArchiveShareRejectsMismatchesBeforePrivateRead(t *testing.T) {
	for _, kind := range []string{"signature", "target", "source", "account", "session", "login", "device", "expired", "binding", "domain"} {
		t.Run(kind, func(t *testing.T) {
			f, req, _ := authorizedArchiveShareFixture(t)
			probe := &archivePrivateReadProbe{SecretStore: f.store}
			f.deps.Store = probe
			switch kind {
			case "signature":
				req.Decision.Signature = "AA=="
			case "target":
				req.SessionPublicKey = f.pubPEM
			case "source":
				req.Ciphertext = "AA=="
			case "account":
				req.AccountID = "99999999-9999-4999-8999-999999999999"
			case "session":
				req.RecoverySessionID = "99999999-9999-4999-8999-999999999999"
			case "login":
				req.Decision.TokenID = "99999999-9999-4999-8999-999999999999"
				req.Decision.Signature = f.sign(t, proto.ArchiveShareDecisionCanonical(*req.Decision))
			case "device":
				if err := f.store.Set(config.Service, config.DeviceID, "99999999-9999-4999-8999-999999999999"); err != nil {
					t.Fatal(err)
				}
			case "expired":
				f.clock.advance(11)
			case "binding":
				if _, _, err := keychain.SetAccountBinding(f.store, req.AccountID, "test", true); err != nil {
					t.Fatal(err)
				}
			case "domain":
				req.Decision.Signature = f.sign(t, "dragpass.group.rewrap|1")
			}
			response := HandleArchiveShareRewrap(f.deps, req)
			if response.Success || response.Data != nil || probe.reads != 0 {
				t.Fatal("invalid authority reached private key or returned output")
			}
		})
	}
}
func TestArchiveShareWithholdsLateCryptoOutput(t *testing.T) {
	f, req, _ := authorizedArchiveShareFixture(t)
	probe := &archivePrivateReadProbe{SecretStore: f.store, beforeRead: func() { f.clock.advance(11) }}
	f.deps.Store = probe
	response := HandleArchiveShareRewrap(f.deps, req)
	if response.Success || response.Data != nil || probe.reads != 1 {
		t.Fatal("expired execution did not withhold output")
	}
	if response := HandleArchiveShareRewrap(f.deps, req); response.Success || probe.reads != 1 {
		t.Fatal("expired attempt was replayed")
	}
}

func TestArchiveShareConcurrentReplayExecutesOnce(t *testing.T) {
	f, req, _ := authorizedArchiveShareFixture(t)
	ready := make(chan struct{}, 2)
	release := make(chan struct{})
	done := make(chan bool, 2)
	for i := 0; i < 2; i++ {
		go func() { ready <- struct{}{}; <-release; done <- HandleArchiveShareRewrap(f.deps, req).Success }()
	}
	<-ready
	<-ready
	close(release)
	count := 0
	for i := 0; i < 2; i++ {
		if <-done {
			count++
		}
	}
	if count != 1 {
		t.Fatal("one challenge did not admit exactly one concurrent caller")
	}
}

func TestOrdinaryArchiveShareRefusesDecisionWithoutRequesterProof(t *testing.T) {
	f, req, _ := authorizedArchiveShareFixture(t)
	req.Decision.RequesterProof = nil
	req.Decision.Signature = f.sign(t, proto.ArchiveShareDecisionCanonical(*req.Decision))
	probe := &archivePrivateReadProbe{SecretStore: f.store}
	f.deps.Store = probe
	res := HandleArchiveShareRewrap(f.deps, req)
	if res.Success || res.Data != nil || probe.reads != 0 {
		t.Fatal("ordinary approval reached private key or returned share without requester proof")
	}
}

func signedRequesterAttachment(t *testing.T, f *auditFixture, req proto.ArchiveShareRewrapRequest, approver *rsa.PublicKey, opt archiveShareFixtureOptions) *proto.ArchiveRequesterProofEnvelope {
	t.Helper()
	requester := req.RequesterAccount()
	account := newTrustKey(t)
	if opt.self {
		if err := keychain.SavePublicKey(f.store, account.pair.PublicKey); err != nil {
			t.Fatal(err)
		}
	}
	device, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	binding := proto.RequestKeyBinding{AccountID: requester, DeviceID: splitTestDevice, PublicKey: base64.StdEncoding.EncodeToString(device)}
	canonical, err := binding.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	rsaSig, err := crypto.SignData(account.priv, canonical)
	if err != nil {
		t.Fatal(err)
	}
	statement, err := keytransparency.EncodeStatement(keytransparency.StatementDeviceRequestKeyBinding, []byte(canonical), []byte(account.pair.PublicKey), rsaSig)
	if err != nil {
		t.Fatal(err)
	}
	enrolled, err := keytransparency.EncodeAccountKeyEnrollmentStatement(requester, account.fingerprint, []byte(account.pair.PublicKey), mustSignEnrollment(t, account, requester))
	if err != nil {
		t.Fatal(err)
	}
	proofs, trust := signedAccountEvidence(t, enrolled, statement)
	f.deps.KeyTransparency = keytransparency.Gate{Trust: trust}
	spki, err := crypto.RewrapKeyFingerprint(req.SessionPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	sid := req.RecoverySessionID
	if opt.signedSession != "" {
		sid = opt.signedSession
	}
	p := archiveRequesterProof{RequesterAccountID: requester, RequesterDeviceID: binding.DeviceID, RequesterAccountPublicKey: account.pair.PublicKey, BindingEvidence: proofs[1], EnrollmentEvidence: &proofs[0]}
	var signed string
	if t := req.RecoveryTarget; t != nil {
		p.GroupID, p.DekVersion = t.GroupID, t.DekVersion
		scope := proto.ArchiveRecoverySessionKeyProof{OrgID: req.OrgID, SessionID: &sid, GroupID: t.GroupID, DekVersion: t.DekVersion, SessionSPKI: spki}
		signed = scope.Canonical(requester, binding.DeviceID, spki)
	} else {
		t := req.SourceTarget
		p.ConfigDigest, p.SessionRound = t.ConfigDigest, t.SessionRound
		scope := proto.ArchiveReconfigurationSessionKeyProof{OrgID: req.OrgID, OperationID: req.SplitOperationID, SessionID: sid, ConfigDigest: t.ConfigDigest}
		if opt.signedOperation != "" {
			scope.OperationID = opt.signedOperation
		}
		if opt.signedConfig != "" {
			scope.ConfigDigest = opt.signedConfig
		}
		round := *t.SessionRound
		if opt.signedRound != nil {
			round = *opt.signedRound
		}
		signed = scope.SourceCanonical(requester, binding.DeviceID, spki, round)
		if opt.materialProof {
			signed = scope.Canonical(requester, binding.DeviceID, spki)
		}
	}
	p.SessionSignatureB64 = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(signed)))
	if opt.alterProof != nil {
		opt.alterProof(&p)
	}
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	wrapped, ciphertext, err := crypto.HybridWrap(approver, raw)
	if err != nil {
		t.Fatal(err)
	}
	return &proto.ArchiveRequesterProofEnvelope{WrappedKey: wrapped, Ciphertext: ciphertext}
}

func TestOrdinaryArchiveShareRejectsInvalidAttachment(t *testing.T) {
	for _, tc := range []struct {
		name  string
		alter func(*archiveRequesterProof)
	}{
		{"missing enrollment", func(p *archiveRequesterProof) { p.EnrollmentEvidence = nil }},
		{"device", func(p *archiveRequesterProof) { p.RequesterDeviceID = testOrgA }},
		{"account", func(p *archiveRequesterProof) { p.RequesterAccountID = testOrgA }},
		{"group", func(p *archiveRequesterProof) { p.GroupID = testOrgA }},
		{"version", func(p *archiveRequesterProof) { p.DekVersion++ }},
		{"session signature", func(p *archiveRequesterProof) {
			p.SessionSignatureB64 = base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
		}},
		{"binding inclusion", func(p *archiveRequesterProof) { p.BindingEvidence.InclusionProofB64 = nil }},
		{"substituted binding signer", func(p *archiveRequesterProof) { p.RequesterAccountPublicKey = newTrustKey(t).pair.PublicKey }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, req, _ := archiveShareFixture(t, archiveShareFixtureOptions{alterProof: tc.alter})
			r := HandleArchiveShareRewrap(f.deps, req)
			if r.Success || r.Data != nil {
				t.Fatal("returned share for an invalid requester proof")
			}
		})
	}
}

func TestArchiveReconfigurationShareNeedsPreparedOperation(t *testing.T) {
	const op = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	f, req, _ := archiveShareFixture(t, archiveShareFixtureOptions{operationID: op})
	req.Decision.SplitOperationID = splitTestDevice
	req.Decision.Signature = f.sign(t, proto.ArchiveShareDecisionCanonical(*req.Decision))
	if r := HandleArchiveShareRewrap(f.deps, req); r.Success || r.Data != nil {
		t.Fatal("accepted another operation")
	}
	req.Decision.SplitOperationID = op
	req.Decision.Signature = f.sign(t, proto.ArchiveShareDecisionCanonical(*req.Decision))
	if r := HandleArchiveShareRewrap(f.deps, req); !r.Success {
		t.Fatal("refused the prepared reconfiguration")
	}
	f, req, _ = authorizedArchiveShareFixture(t)
	req.Decision.Purpose = "reconfiguration"
	req.Decision.RequesterProof = nil
	req.Decision.SplitOperationID = op
	req.SplitOperationID = op
	req.RecoveryTarget = nil
	req.Decision.Signature = f.sign(t, proto.ArchiveShareDecisionCanonical(*req.Decision))
	if r := HandleArchiveShareRewrap(f.deps, req); r.Success || r.Data != nil {
		t.Fatal("reclassified an ordinary challenge")
	}
}

func TestOrdinaryArchiveShareRefusesValidSignatureFromAnotherReservation(t *testing.T) {
	f, req, _ := archiveShareFixture(t, archiveShareFixtureOptions{signedSession: "99999999-9999-4999-8999-999999999999"})
	if r := HandleArchiveShareRewrap(f.deps, req); r.Success || r.Data != nil || r.ErrorCode != "not_found" {
		t.Fatal("valid signature on another reservation authorized release")
	}
}

func TestOrdinaryArchiveShareRefusesAttachmentChangedAfterIssuance(t *testing.T) {
	f, req, _ := authorizedArchiveShareFixture(t)
	req.Decision.RequesterProof.Ciphertext = "AQ=="
	probe := &archivePrivateReadProbe{SecretStore: f.store}
	f.deps.Store = probe
	if r := HandleArchiveShareRewrap(f.deps, req); r.Success || r.Data != nil || probe.reads != 0 {
		t.Fatal("changed ciphertext reached the approver archive key")
	}
}

func TestOrdinaryArchiveShareRespectsVerifiedPeersPolicy(t *testing.T) {
	f, req, _ := authorizedArchiveShareFixture(t)
	if err := keychain.SavePeerKeyPolicy(f.store, keychain.PeerKeyPolicy{RequireVerifiedPeers: true}); err != nil {
		t.Fatal(err)
	}
	if r := HandleArchiveShareRewrap(f.deps, req); r.Success || r.Data != nil {
		t.Fatal("strict peer policy released a share on first contact")
	}
	if _, err := keychain.GetPeerKeyPin(f.store, req.AccountID, req.RecoveryTarget.RequesterAccountID); !errors.Is(err, keychain.ErrSecretNotFound) {
		t.Fatal("strict refusal persisted a pin")
	}
	f, req, _ = archiveShareFixture(t, archiveShareFixtureOptions{self: true})
	if err := keychain.SavePeerKeyPolicy(f.store, keychain.PeerKeyPolicy{RequireVerifiedPeers: true}); err != nil {
		t.Fatal(err)
	}
	if r := HandleArchiveShareRewrap(f.deps, req); !r.Success {
		t.Fatal("valid signed proof for the owner's own active key refused")
	}
}

func TestOrdinaryArchivePrepareOffersOnlyProvenRequesterPin(t *testing.T) {
	f, req, _ := authorizedArchiveShareFixture(t)
	decision := req.Decision
	if r := HandleArchiveShareRewrap(f.deps, req); !r.Success {
		t.Fatal("first approval failed")
	}
	req.Decision = nil
	prepare := proto.ArchiveSharePrepareRequest{Request: req, TokenID: decision.TokenID, SessionIssuedAtNanos: decision.SessionIssuedAtNanos}
	readHint := func() string {
		t.Helper()
		r := HandleArchiveSharePrepare(f.deps, prepare)
		if !r.Success {
			t.Fatal("prepare failed")
		}
		raw, err := json.Marshal(r.Data)
		if err != nil {
			t.Fatal(err)
		}
		var v struct {
			Pin string `json:"requester_pin_fingerprint"`
		}
		if json.Unmarshal(raw, &v) != nil {
			t.Fatal("invalid response")
		}
		return v.Pin
	}
	pin := mustGetPin(t, f.deps, req.AccountID, req.RecoveryTarget.RequesterAccountID)
	if hint := readHint(); hint != pin.Fingerprint {
		t.Fatal("proven account key omitted from prepare")
	}
	f.deps.KeyTransparency.Trust.ConfigDigest = "different-trust"
	if hint := readHint(); hint != "" {
		t.Fatal("disclosed a stale proof as an enrollment anchor")
	}
}

func TestSourceShareRefusesDecisionWithoutRequesterProof(t *testing.T) {
	f, req, _ := archiveShareFixture(t, archiveShareFixtureOptions{operationID: splitTestOperation})
	req.Decision.RequesterProof = nil
	req.Decision.Signature = f.sign(t, proto.ArchiveShareDecisionCanonical(*req.Decision))
	probe := &archivePrivateReadProbe{SecretStore: f.store}
	f.deps.Store = probe
	result := HandleArchiveShareRewrap(f.deps, req)
	if result.Success || result.Data != nil || probe.reads != 0 {
		t.Fatal("source share accepted a decision without requester evidence")
	}
}

func TestSourceShareVerifiesSignedRoundAndPurpose(t *testing.T) {
	const op = splitTestOperation
	previous := 0
	for name, opt := range map[string]archiveShareFixtureOptions{
		"other signed operation": {operationID: op, signedOperation: testOrgA},
		"other signed config":    {operationID: op, signedConfig: strings.Repeat("b", 64)},
		"other session":          {operationID: op, signedSession: testOrgA},
		"earlier round":          {operationID: op, sourceRound: 1, signedRound: &previous},
		"material release":       {operationID: op, materialProof: true},
		"missing round zero":     {operationID: op, alterProof: func(p *archiveRequesterProof) { p.SessionRound = nil }},
		"other config":           {operationID: op, alterProof: func(p *archiveRequesterProof) { p.ConfigDigest = strings.Repeat("b", 64) }},
		"missing enrollment":     {operationID: op, alterProof: func(p *archiveRequesterProof) { p.EnrollmentEvidence = nil }},
	} {
		t.Run(name, func(t *testing.T) {
			f, req, _ := archiveShareFixture(t, opt)
			res := HandleArchiveShareRewrap(f.deps, req)
			if res.Success || res.Data != nil {
				t.Fatal("source share escaped without an exact requester proof")
			}
		})
	}
	f, req, _ := archiveShareFixture(t, archiveShareFixtureOptions{operationID: op, sourceRound: 1})
	*req.SourceTarget.SessionRound = 2
	if r := HandleArchiveShareRewrap(f.deps, req); r.Success || r.Data != nil {
		t.Fatal("changed card round released a share")
	}
	*req.SourceTarget.SessionRound = 1
	if r := HandleArchiveShareRewrap(f.deps, req); !r.Success {
		t.Fatal("valid supplementary proof refused")
	}
}
