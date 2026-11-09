package handlers

import (
	"strings"
	"sync"
	"testing"

	"github.com/dragpass/keeper/config"
	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

const (
	splitTestDevice    = "55555555-5555-4555-8555-555555555555"
	splitTestToken     = "66666666-6666-4666-8666-666666666666"
	splitTestOperation = "77777777-7777-4777-8777-777777777777"
	splitTestConfig    = "c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00"
	splitTestOther     = "99999999-9999-4999-8999-999999999999"
)

var splitTestRecipientAccounts = []string{
	"a1111111-1111-4111-8111-111111111111",
	"a2222222-2222-4222-8222-222222222222",
	"a3333333-3333-4333-8333-333333333333",
}

// splitAccessProbe counts reads of archive private slots and split journals,
// and every write or delete, so a refused split proves it touched neither.
type splitAccessProbe struct {
	keychain.SecretStore
	mu                         sync.Mutex
	private                    map[string]bool
	privateReads, journalReads int
	sets, deletes              int
	beforePrivateRead          func()
	privateDeletes             int
	// deleteHook runs outside the probe lock before each delete; an error
	// fails that delete.
	deleteHook func(account string) error
}

func (p *splitAccessProbe) Get(service, account string) (string, error) {
	p.mu.Lock()
	if p.private[account] {
		p.privateReads++
		if p.beforePrivateRead != nil {
			p.beforePrivateRead()
		}
	}
	if strings.HasPrefix(account, "archive_quorum_split_pending:") {
		p.journalReads++
	}
	p.mu.Unlock()
	return p.SecretStore.Get(service, account)
}

func (p *splitAccessProbe) Set(service, account, value string) error {
	p.mu.Lock()
	p.sets++
	p.mu.Unlock()
	return p.SecretStore.Set(service, account, value)
}

func (p *splitAccessProbe) Delete(service, account string) error {
	p.mu.Lock()
	p.deletes++
	if p.private[account] {
		p.privateDeletes++
	}
	hook := p.deleteHook
	p.mu.Unlock()
	if hook != nil {
		if err := hook(account); err != nil {
			return err
		}
	}
	return p.SecretStore.Delete(service, account)
}

type splitFixture struct {
	*auditFixture
	admins    []*crypto.KeyPair
	archive   string // active archive public PEM
	probe     *splitAccessProbe
	request   proto.ArchiveKeySplitRequest
	nextNonce byte
}

func newSplitFixture(t *testing.T) *splitFixture {
	t.Helper()
	f := &splitFixture{auditFixture: newAuditFixture(t)}
	f.deps.ArchiveSplitChallenges = NewArchiveShareChallengeStore()
	f.deps.ArchiveProofChallenges = NewArchiveShareChallengeStore()
	if err := f.store.Set(config.Service, config.DeviceID, splitTestDevice); err != nil {
		t.Fatal(err)
	}
	seedActiveArchiveKey(t, f.deps)
	beginOrg(t, f.deps, f.v.OrgID)
	if r := HandleArchiveKeyRotateCommit(f.deps, proto.ArchiveKeyRotateCommitRequest{OrgID: f.v.OrgID}); !r.Success {
		t.Fatalf("commit org key: %s", r.Error)
	}
	_, pub, found, err := keychain.FindArchiveKey(f.store, keychain.OrgArchiveActiveCandidates(f.v.OrgID))
	if err != nil || !found {
		t.Fatal("org archive key missing")
	}
	f.archive = pub
	var pems []string
	f.admins, pems = genAdminKeys(t, len(splitTestRecipientAccounts))
	f.request = proto.ArchiveKeySplitRequest{
		OperationID: splitTestOperation, AccountID: f.v.AccountID, OrgID: f.v.OrgID, ThresholdN: 2,
		RecipientPublicKeys: pems, RecipientAccountIDs: append([]string(nil), splitTestRecipientAccounts...),
		ConfigDigest: splitTestConfig,
	}
	private := map[string]bool{}
	for _, slot := range keychain.OrgArchiveActiveCandidates(f.v.OrgID) {
		private[slot.PrivateAccount] = true
	}
	f.probe = &splitAccessProbe{SecretStore: f.store, private: private}
	f.deps.Store = f.probe
	return f
}

// authorize prepares the request and returns it carrying a valid decision.
func (f *splitFixture) authorize(t *testing.T, req proto.ArchiveKeySplitRequest) proto.ArchiveKeySplitRequest {
	t.Helper()
	req.Decision = nil
	response := HandleArchiveSplitPrepare(f.deps, proto.ArchiveSplitPrepareRequest{Request: req, TokenID: splitTestToken, SessionIssuedAtNanos: 123})
	if !response.Success {
		t.Fatalf("valid split preparation refused: %s %s", response.ErrorCode, response.Error)
	}
	prepared := response.Data.(proto.ArchiveSplitPrepareResponseData)
	spki, err := crypto.RewrapKeyFingerprint(f.archive)
	if err != nil {
		t.Fatal(err)
	}
	recipients := make([]proto.ArchiveSplitRecipient, len(req.RecipientPublicKeys))
	for i, pem := range req.RecipientPublicKeys {
		recipients[i] = proto.ArchiveSplitRecipient{AccountID: req.RecipientAccountIDs[i], KeyFingerprint: crypto.AccountKeyFingerprint([]byte(pem))}
	}
	now := f.clock.now().Unix()
	decision := proto.ArchiveSplitDecision{
		Challenge: prepared.Challenge, AccountID: req.AccountID, DeviceID: splitTestDevice, TokenID: splitTestToken,
		SessionIssuedAtNanos: 123, OrgID: req.OrgID, OperationID: req.OperationID, ConfigDigest: req.ConfigDigest,
		ArchiveKeyFingerprint: crypto.AccountKeyFingerprint([]byte(f.archive)), ArchiveKeySPKIFingerprint: spki,
		ThresholdN: req.ThresholdN, Recipients: recipients, RequestDigest: prepared.RequestDigest,
		IssuedAt: now, ExpiresAt: now + proto.ArchiveShareDecisionTTLSeconds, ServerKeyVersion: 1,
	}
	decision.Signature = f.sign(t, proto.ArchiveSplitDecisionCanonical(decision))
	req.Decision = &decision
	return req
}

func (f *splitFixture) resign(t *testing.T, req proto.ArchiveKeySplitRequest) {
	t.Helper()
	req.Decision.Signature = f.sign(t, proto.ArchiveSplitDecisionCanonical(*req.Decision))
}

func (f *splitFixture) resetProbe() {
	f.probe.mu.Lock()
	defer f.probe.mu.Unlock()
	f.probe.privateReads, f.probe.journalReads, f.probe.sets, f.probe.deletes = 0, 0, 0, 0
}

func TestArchiveKeySplitAcceptsValidSignedDecision(t *testing.T) {
	f := newSplitFixture(t)
	req := f.authorize(t, f.request)
	response := HandleArchiveKeySplit(f.deps, req)
	if !response.Success {
		t.Fatalf("valid signed split decision refused: %s %s", response.ErrorCode, response.Error)
	}
	data := response.Data.(proto.ArchiveKeySplitResponseData)
	if len(data.Shares) != len(splitTestRecipientAccounts) || data.KeyFingerprint != req.Decision.ArchiveKeyFingerprint {
		t.Fatal("authorized split returned an unexpected result")
	}
	for i, share := range data.Shares {
		if share.RecipientFingerprint != req.Decision.Recipients[i].KeyFingerprint {
			t.Fatalf("share %d wrapped to an unbound recipient", i)
		}
	}
	if f.probe.deletes != 0 {
		t.Fatal("authorized split deleted a slot before finalization")
	}
}

func TestArchiveKeySplitRefusesInvalidAuthorityBeforePrivateRead(t *testing.T) {
	cases := map[string]func(t *testing.T, f *splitFixture, req *proto.ArchiveKeySplitRequest){
		"missing": func(t *testing.T, f *splitFixture, req *proto.ArchiveKeySplitRequest) { req.Decision = nil },
		"forged": func(t *testing.T, f *splitFixture, req *proto.ArchiveKeySplitRequest) {
			req.Decision.Signature = "AA=="
		},
		"other domain": func(t *testing.T, f *splitFixture, req *proto.ArchiveKeySplitRequest) {
			req.Decision.Signature = f.sign(t, "dragpass.archive.share.rewrap|1")
		},
		"expired": func(t *testing.T, f *splitFixture, req *proto.ArchiveKeySplitRequest) { f.clock.advance(11) },
		"unprepared challenge": func(t *testing.T, f *splitFixture, req *proto.ArchiveKeySplitRequest) {
			req.Decision.Challenge = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
			f.resign(t, *req)
		},
		"requester": func(t *testing.T, f *splitFixture, req *proto.ArchiveKeySplitRequest) {
			req.AccountID, req.Decision.AccountID = splitTestOther, splitTestOther
			f.resign(t, *req)
		},
		"device": func(t *testing.T, f *splitFixture, req *proto.ArchiveKeySplitRequest) {
			req.Decision.DeviceID = splitTestOther
			f.resign(t, *req)
		},
		"live device": func(t *testing.T, f *splitFixture, req *proto.ArchiveKeySplitRequest) {
			if err := f.store.Set(config.Service, config.DeviceID, splitTestOther); err != nil {
				t.Fatal(err)
			}
		},
		"token": func(t *testing.T, f *splitFixture, req *proto.ArchiveKeySplitRequest) {
			req.Decision.TokenID = splitTestOther
			f.resign(t, *req)
		},
		"session": func(t *testing.T, f *splitFixture, req *proto.ArchiveKeySplitRequest) {
			req.Decision.SessionIssuedAtNanos = 124
			f.resign(t, *req)
		},
		"signed out": func(t *testing.T, f *splitFixture, req *proto.ArchiveKeySplitRequest) {
			if _, _, err := keychain.SetAccountBinding(f.store, req.AccountID, "test", true); err != nil {
				t.Fatal(err)
			}
		},
		"operation": func(t *testing.T, f *splitFixture, req *proto.ArchiveKeySplitRequest) {
			req.OperationID, req.Decision.OperationID = splitTestOther, splitTestOther
			f.resign(t, *req)
		},
		"config digest": func(t *testing.T, f *splitFixture, req *proto.ArchiveKeySplitRequest) {
			req.Decision.ConfigDigest = strings.Repeat("ab", 32)
			f.resign(t, *req)
		},
		"archive key fingerprint": func(t *testing.T, f *splitFixture, req *proto.ArchiveKeySplitRequest) {
			req.Decision.ArchiveKeyFingerprint = strings.Repeat("ab", 32)
			f.resign(t, *req)
		},
		"archive key spki": func(t *testing.T, f *splitFixture, req *proto.ArchiveKeySplitRequest) {
			req.Decision.ArchiveKeySPKIFingerprint = strings.Repeat("ab", 32)
			f.resign(t, *req)
		},
		"threshold": func(t *testing.T, f *splitFixture, req *proto.ArchiveKeySplitRequest) {
			req.ThresholdN, req.Decision.ThresholdN = 3, 3
			f.resign(t, *req)
		},
		"decision threshold": func(t *testing.T, f *splitFixture, req *proto.ArchiveKeySplitRequest) {
			req.Decision.ThresholdN = 3
			f.resign(t, *req)
		},
		"participant order": func(t *testing.T, f *splitFixture, req *proto.ArchiveKeySplitRequest) {
			r := req.Decision.Recipients
			r[0].AccountID, r[1].AccountID = r[1].AccountID, r[0].AccountID
			f.resign(t, *req)
		},
		"participant key": func(t *testing.T, f *splitFixture, req *proto.ArchiveKeySplitRequest) {
			req.Decision.Recipients[2].KeyFingerprint = strings.Repeat("ab", 32)
			f.resign(t, *req)
		},
		"request recipient key": func(t *testing.T, f *splitFixture, req *proto.ArchiveKeySplitRequest) {
			_, pems := genAdminKeys(t, 1)
			req.RecipientPublicKeys = append(append([]string(nil), req.RecipientPublicKeys[:2]...), pems[0])
		},
		"request digest": func(t *testing.T, f *splitFixture, req *proto.ArchiveKeySplitRequest) {
			req.Decision.RequestDigest = strings.Repeat("ab", 32)
			f.resign(t, *req)
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := newSplitFixture(t)
			req := f.authorize(t, f.request)
			mutate(t, f, &req)
			f.resetProbe()
			response := HandleArchiveKeySplit(f.deps, req)
			assertSplitRefusedUntouched(t, f, response)
		})
	}
}

func TestArchiveKeySplitRefusesReplayedDecision(t *testing.T) {
	f := newSplitFixture(t)
	req := f.authorize(t, f.request)
	if first := HandleArchiveKeySplit(f.deps, req); !first.Success {
		t.Fatalf("valid split refused: %s", first.Error)
	}
	f.resetProbe()
	assertSplitRefusedUntouched(t, f, HandleArchiveKeySplit(f.deps, req))
}

func TestArchiveKeySplitConcurrentReplayExecutesOnce(t *testing.T) {
	f := newSplitFixture(t)
	req := f.authorize(t, f.request)
	ready := make(chan struct{}, 2)
	release := make(chan struct{})
	done := make(chan bool, 2)
	for i := 0; i < 2; i++ {
		go func() { ready <- struct{}{}; <-release; done <- HandleArchiveKeySplit(f.deps, req).Success }()
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
		t.Fatalf("one split challenge admitted %d callers", count)
	}
}

func TestArchiveKeySplitWithholdsOutputAfterLateExpiry(t *testing.T) {
	f := newSplitFixture(t)
	req := f.authorize(t, f.request)
	f.probe.beforePrivateRead = func() { f.clock.advance(11) }
	response := HandleArchiveKeySplit(f.deps, req)
	if response.Success || response.Data != nil {
		t.Fatal("split output returned after its decision expired")
	}
}

func TestArchiveSplitPrepareRefusesOtherRequester(t *testing.T) {
	f := newSplitFixture(t)
	req := f.request
	req.AccountID = splitTestOther
	f.resetProbe()
	response := HandleArchiveSplitPrepare(f.deps, proto.ArchiveSplitPrepareRequest{Request: req, TokenID: splitTestToken, SessionIssuedAtNanos: 123})
	if response.Success || f.probe.privateReads != 0 || f.probe.sets != 0 {
		t.Fatal("preparation accepted a request for another account")
	}
	if f.deps.ArchiveSplitChallenges.Len() != 0 {
		t.Fatal("refused preparation left a challenge")
	}
}

func assertSplitRefusedUntouched(t *testing.T, f *splitFixture, response proto.BaseResponse) {
	t.Helper()
	if response.Success || response.Data != nil {
		t.Fatal("invalid split authority returned shares")
	}
	if response.ErrorCode != string(errs.ErrCodeArchiveSplitAuthorityRequired) {
		t.Fatalf("error code = %q", response.ErrorCode)
	}
	f.probe.mu.Lock()
	defer f.probe.mu.Unlock()
	if f.probe.privateReads != 0 || f.probe.journalReads != 0 || f.probe.sets != 0 || f.probe.deletes != 0 {
		t.Fatalf("refused split touched secrets: private=%d journal=%d sets=%d deletes=%d",
			f.probe.privateReads, f.probe.journalReads, f.probe.sets, f.probe.deletes)
	}
}
