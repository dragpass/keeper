package handlers

import (
	"regexp"
	"sort"
	"strings"
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

// preexistingOversizeItems names item kinds written by code outside the
// lv90 rotation, supplement and finalize handlers that already exceed
// keychainItemLimit in these fixtures. They are measured and logged, not
// refused, so this guard covers the new item kinds without hiding the
// earlier defect.
var preexistingOversizeItems = []string{"archive_quorum_split_pending:"}

var keychainItemUUID = regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)

// sizeLimitedStore refuses a value over keychainItemLimit the way the real
// keyring does (ErrSetDataTooBig, nothing stored) and records the largest
// value written per item kind (the account with UUIDs replaced).
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
	kind := keychainItemUUID.ReplaceAllString(account, "<uuid>")
	s.mu.Lock()
	if len(value) > s.largest[kind] {
		s.largest[kind] = len(value)
	}
	exempt := false
	for _, prefix := range preexistingOversizeItems {
		exempt = exempt || strings.HasPrefix(account, prefix)
	}
	if len(value) > keychainItemLimit && !exempt {
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
