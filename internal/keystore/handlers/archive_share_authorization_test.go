package handlers

import (
	"github.com/dragpass/keeper/config"
	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
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
	prepare := proto.ArchiveSharePrepareRequest{Request: req, TokenID: "66666666-6666-4666-8666-666666666666", SessionIssuedAtNanos: 123}
	response := HandleArchiveSharePrepare(f.deps, prepare)
	if !response.Success {
		t.Fatal("valid preparation refused")
	}
	prepared := response.Data.(proto.ArchiveSharePrepareResponseData)
	decision := proto.ArchiveShareDecision{Challenge: prepared.Challenge, AccountID: req.AccountID, DeviceID: device, TokenID: prepare.TokenID, SessionIssuedAtNanos: 123, OrgID: req.OrgID, RecoverySessionID: req.RecoverySessionID, QuorumID: "88888888-8888-4888-8888-888888888888", RequestDigest: prepared.RequestDigest, IssuedAt: f.clock.now().Unix(), ExpiresAt: f.clock.now().Unix() + 10, ServerKeyVersion: 1}
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
