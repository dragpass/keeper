package handlers

import (
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"sync"
	"testing"

	"github.com/zalando/go-keyring"

	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// keychainItemLimit is the smallest value size the vendored go-keyring
// v0.2.6 accepts on any release platform. Windows refuses a password over
// 2560 bytes (keyring_windows.go:29). macOS stores the 18-byte prefix
// "go-keyring-base64:" plus the Base64 value and refuses more than 4096 bytes
// (keyring_darwin.go:70-71), so a raw value over 3057 bytes fails there.
// The Linux Secret Service backend sets no limit in the library.
const keychainItemLimit = 2560

var keychainItemUUID = regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)

// keychainItemPartIndex folds the index of a split journal part into its kind.
var keychainItemPartIndex = regexp.MustCompile(`:part:[0-9]+$`)

// sizeLimitedStore refuses a value over keychainItemLimit the way the real
// keyring does (ErrSetDataTooBig, nothing stored) and records the largest
// value written per item kind (the account with UUIDs and part indexes
// replaced).
type sizeLimitedStore struct {
	keychain.SecretStore
	mu      sync.Mutex
	largest map[string]int
	refused []string
}

func newSizeLimitedStore(inner keychain.SecretStore) *sizeLimitedStore {
	return &sizeLimitedStore{SecretStore: inner, largest: map[string]int{}}
}

func (s *sizeLimitedStore) Set(service, account, value string) error {
	kind := keychainItemPartIndex.ReplaceAllString(keychainItemUUID.ReplaceAllString(account, "<uuid>"), ":part:<n>")
	s.mu.Lock()
	if len(value) > s.largest[kind] {
		s.largest[kind] = len(value)
	}
	if len(value) > keychainItemLimit {
		s.refused = append(s.refused, kind)
		s.mu.Unlock()
		return keyring.ErrSetDataTooBig
	}
	s.mu.Unlock()
	return s.SecretStore.Set(service, account, value)
}

// check fails the test for every refused write and logs the measured sizes.
func (s *sizeLimitedStore) check(t *testing.T) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	kinds := make([]string, 0, len(s.largest))
	for kind := range s.largest {
		kinds = append(kinds, kind)
	}
	sort.Strings(kinds)
	for _, kind := range kinds {
		t.Logf("keychain item %s: largest value %d bytes (limit %d)", kind, s.largest[kind], keychainItemLimit)
	}
	for _, kind := range s.refused {
		t.Errorf("keychain item %s exceeds the %d byte platform limit", kind, keychainItemLimit)
	}
}

// splitSizeRecipientCounts are the recipient counts measured: small quorums
// and the largest count a split accepts (proto.ArchiveSplitMaxRecipients,
// the server's participant cap).
var splitSizeRecipientCounts = []int{2, 3, 5, 32}

var (
	splitSizeKeysOnce sync.Once
	splitSizeKeys     []string
	splitSizeAccounts []string
)

// splitSizeRecipients returns n distinct RSA-2048 recipient public keys and
// account IDs, generated once for the largest count.
func splitSizeRecipients(t *testing.T, n int) ([]string, []string) {
	t.Helper()
	splitSizeKeysOnce.Do(func() {
		max := splitSizeRecipientCounts[len(splitSizeRecipientCounts)-1]
		splitSizeKeys = make([]string, max)
		splitSizeAccounts = make([]string, max)
		var wg sync.WaitGroup
		errs := make([]error, max)
		for i := range max {
			splitSizeAccounts[i] = fmt.Sprintf("b%07x-0000-4000-8000-%012x", i, i)
			wg.Add(1)
			go func() {
				defer wg.Done()
				kp, err := crypto.GenerateRSAKeyPair()
				if err == nil {
					splitSizeKeys[i] = kp.PublicKey
				}
				errs[i] = err
			}()
		}
		wg.Wait()
		for _, err := range errs {
			if err != nil {
				splitSizeKeys = nil
			}
		}
	})
	if len(splitSizeKeys) < n {
		t.Fatal("recipient key generation failed")
	}
	return append([]string(nil), splitSizeKeys[:n]...), append([]string(nil), splitSizeAccounts[:n]...)
}

// Every item an activation split and its finalization write, and every item a
// reconfiguration split and its closure write, fits the smallest platform
// limit at every measured recipient count, and a retry of the split returns
// the same shares.
func TestArchiveSplitKeychainItemsFitPlatformLimitAtEveryRecipientCount(t *testing.T) {
	for _, n := range splitSizeRecipientCounts {
		t.Run(fmt.Sprintf("activation/%d", n), func(t *testing.T) {
			f := newSplitFixture(t)
			f.request.RecipientPublicKeys, f.request.RecipientAccountIDs = splitSizeRecipients(t, n)
			limited := newSizeLimitedStore(f.deps.Store)
			f.deps.Store = limited
			first := HandleArchiveKeySplit(f.deps, f.authorize(t, f.request))
			if !first.Success {
				limited.check(t)
				t.Fatalf("split with %d recipients: %s %s", n, first.ErrorCode, first.Error)
			}
			again := HandleArchiveKeySplit(f.deps, f.authorize(t, f.request))
			if !again.Success || !reflect.DeepEqual(first.Data, again.Data) {
				t.Fatal("split retry did not return the journaled shares")
			}
			shares := first.Data.(proto.ArchiveKeySplitResponseData).Shares
			ff := &finalizeFixture{splitFixture: f, split: first.Data.(proto.ArchiveKeySplitResponseData)}
			ff.spki, _ = crypto.RewrapKeyFingerprint(f.archive)
			if len(shares) != n {
				t.Fatal("share count")
			}
			if r := HandleArchiveSplitFinalize(f.deps, ff.receipt(t, nil)); !r.Success {
				limited.check(t)
				t.Fatalf("finalize: %s %s", r.ErrorCode, r.Error)
			}
			limited.check(t)
		})
		t.Run(fmt.Sprintf("reconfiguration/%d", n), func(t *testing.T) {
			f := newSplitFixture(t)
			f.request.RecipientPublicKeys, f.request.RecipientAccountIDs = splitSizeRecipients(t, n)
			limited := newSizeLimitedStore(f.deps.Store)
			f.deps.Store = limited
			req, _ := f.authorizeReconfiguration(t)
			first := HandleArchiveKeySplit(f.deps, req)
			if !first.Success {
				limited.check(t)
				t.Fatalf("reconfiguration split with %d recipients: %s %s", n, first.ErrorCode, first.Error)
			}
			d := req.ReconfigurationDecision
			closure := proto.ArchiveSplitClosureReceipt{Kind: req.Kind, OperationID: req.OperationID, OrgID: req.OrgID, Status: proto.ArchiveSplitClosedCancelled, SourceConfigDigest: d.SourceConfigDigest, TargetKeySPKIFingerprint: d.TargetKeySPKIFingerprint, ServerKeyVersion: 1}
			closure.Signature = f.sign(t, proto.ArchiveSplitClosureReceiptCanonical(closure))
			if r := HandleArchiveSplitAbandon(f.deps, proto.ArchiveSplitAbandonRequest{OrgID: req.OrgID, Receipt: &closure}); !r.Success {
				limited.check(t)
				t.Fatalf("closure: %s %s", r.ErrorCode, r.Error)
			}
			limited.check(t)
		})
	}
}

// Every item the session, supplement, rotation and finalize handlers write
// must fit the smallest platform limit, measured through the real handlers.
func TestArchiveReconfigurationKeychainItemsFitPlatformLimit(t *testing.T) {
	f := newSplitFixture(t)
	f.deps.ArchiveRotationChallenges = NewArchiveShareChallengeStore()
	limited := newSizeLimitedStore(f.deps.Store)
	f.deps.Store = limited
	split, _ := f.authorizeReconfiguration(t)
	splitResult := HandleArchiveKeySplit(f.deps, split)
	if !splitResult.Success {
		t.Fatal("split", splitResult.ErrorCode)
	}
	prior := beginOrgSession(t, f.deps, split.OrgID)
	if r := HandleArchiveSessionSetExpiry(f.deps, proto.ArchiveSessionSetExpiryRequest{OrgID: split.OrgID, Fingerprint: prior.Fingerprint, ExpiresAt: prior.ExpiresAt}); !r.Success {
		t.Fatal("set expiry", r.ErrorCode)
	}
	prev, _ := crypto.RewrapKeyFingerprint(prior.SessionPublicKey)
	if r := HandleRequestKeyGenerate(f.deps, proto.RequestKeyGenerateRequest{}); !r.Success {
		t.Fatal(r.ErrorCode)
	}
	if r := HandleArchiveReconfigurationSessionKeyProof(f.deps, proto.ArchiveReconfigurationSessionKeyProof{OrgID: split.OrgID, OperationID: split.OperationID, ConfigDigest: split.ConfigDigest, SessionID: splitTestOther, SessionSPKI: prev}); !r.Success {
		t.Fatal("proof", r.ErrorCode)
	}
	params := proto.SupplementPrevious{OrgID: split.OrgID, OperationID: split.OperationID, ConfigDigest: split.ConfigDigest, PreviousSessionID: splitTestOther, PreviousSPKI: prev}
	prepared := HandleSupplementPrepare(f.deps, proto.SupplementPrepare{SupplementPrevious: params})
	if !prepared.Success {
		limited.check(t)
		t.Fatal("supplement prepare", prepared.ErrorCode)
	}
	cand := prepared.Data.(proto.SupplementCandidate)
	receipt := proto.SupplementReceipt{SupplementPrevious: params, AccountID: f.v.AccountID, DeviceID: splitTestDevice, SessionID: splitTestToken, SPKI: cand.SPKI, Round: 1, ExpiresAt: f.deps.Now().Unix() + 600, Version: 1}
	receipt.Signature = f.sign(t, receipt.Canonical())
	if r := HandleSupplementPromote(f.deps, proto.SupplementPromote{Receipt: receipt}); !r.Success {
		limited.check(t)
		t.Fatal("supplement promote", r.ErrorCode)
	}
	next := params
	next.PreviousSessionID, next.PreviousSPKI = receipt.SessionID, cand.SPKI
	if r := HandleSupplementPrepare(f.deps, proto.SupplementPrepare{SupplementPrevious: next, PreviousRound: 1}); !r.Success {
		limited.check(t)
		t.Fatal("second supplement prepare", r.ErrorCode)
	}
	SweepExpiredArchiveSession(f.deps)

	rot := newRotationRun(t, f, split, f.archiveSourcePEM(t, split.OrgID))
	if r := rot.run(rot.decision(t)); !r.Success {
		limited.check(t)
		t.Fatal("rotation", r.ErrorCode)
	}
	if err := keychain.OrgArchiveActiveSlot(split.OrgID).DeletePrivate(f.store); err != nil && err != keychain.ErrSecretNotFound {
		t.Fatal(err)
	}
	shares := splitResult.Data.(proto.ArchiveKeySplitResponseData).Shares
	if r := f.finalize(f.finalizationReceipt(t, split, shares, nil)); !r.Success {
		limited.check(t)
		t.Fatal("finalize", r.ErrorCode)
	}
	limited.check(t)
}
