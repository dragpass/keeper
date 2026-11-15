// archive_key_generate_org_test.go — org-scoped first-time archive key
// generation (lv96).
//
// A person-verified quorum split accepts only an org's own archive slot, so
// an org created or enabled in the App must start on a key in
// org_archive_*:<org_id>. Generating for one org must never touch another
// org's slot or the device-wide slot other orgs may still use.

package handlers

import (
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dragpass/keeper/internal/keystore/crypto"

	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/testdouble"
)

func generateFor(t *testing.T, deps Deps, orgID string) proto.ArchiveKeyGenerateResponseData {
	t.Helper()
	resp := HandleArchiveKeyGenerate(deps, proto.ArchiveKeyGenerateRequest{OrgID: orgID})
	if !resp.Success {
		t.Fatalf("generate for %q: %s", orgID, resp.Error)
	}
	return resp.Data.(proto.ArchiveKeyGenerateResponseData)
}

func TestArchiveKeyGenerate_OrgGetsItsOwnSlotAndLeavesOthers(t *testing.T) {
	deps, _, store := newTestDeps(t)
	device := seedActiveArchiveKey(t, deps)

	a := generateFor(t, deps, testOrgA)
	if a.Scope != keychain.ArchiveScopeOrg || a.Fingerprint == device.Fingerprint {
		t.Fatalf("org A key: scope %q, same as device key: %v", a.Scope, a.Fingerprint == device.Fingerprint)
	}
	privA, err := keychain.OrgArchiveActiveSlot(testOrgA).GetPrivate(store)
	if err != nil || privA == "" {
		t.Fatalf("org A private slot: %v", err)
	}

	b := generateFor(t, deps, testOrgB)
	if b.Scope != keychain.ArchiveScopeOrg || b.Fingerprint == a.Fingerprint || b.Fingerprint == device.Fingerprint {
		t.Fatalf("org B must get its own key: %+v", b)
	}
	if got, _ := keychain.OrgArchiveActiveSlot(testOrgA).GetPrivate(store); got != privA {
		t.Fatal("generating for org B changed org A's private key")
	}
	if pub, _ := keychain.GetArchivePublicKey(store); pub != device.PublicKey {
		t.Fatal("an org-scoped generate replaced the device-wide key")
	}
	st := HandleArchiveKeyStatus(deps, proto.ArchiveKeyStatusRequest{OrgID: testOrgA}).Data.(proto.ArchiveKeyStatusResponseData)
	if st.Scope != keychain.ArchiveScopeOrg || st.Fingerprint != a.Fingerprint {
		t.Fatalf("status for org A: %+v", st)
	}
}

// An org that already holds its own key gets that key back: a repeated
// generate (a retried enable, a second create attempt) never replaces it.
func TestArchiveKeyGenerate_OrgExistingSlotIsReturnedUnchanged(t *testing.T) {
	deps, _, store := newTestDeps(t)
	first := generateFor(t, deps, testOrgA)
	before := store.Snapshot()

	again := generateFor(t, deps, testOrgA)
	if again != first {
		t.Fatalf("second generate returned another key: %+v vs %+v", again, first)
	}
	if !reflect.DeepEqual(before, store.Snapshot()) {
		t.Fatal("a repeated generate changed the keychain")
	}
}

// Without org_id the action keeps its device-wide contract (the Extension and
// older Apps call it this way).
func TestArchiveKeyGenerate_WithoutOrgStaysDeviceWide(t *testing.T) {
	deps, _, store := newTestDeps(t)
	device := seedActiveArchiveKey(t, deps)
	if device.Scope != "" && device.Scope != keychain.ArchiveScopeDevice {
		t.Fatalf("device-wide generate scope %q", device.Scope)
	}
	if _, err := keychain.OrgArchiveActiveSlot(testOrgA).GetPublic(store); !errors.Is(err, keychain.ErrSecretNotFound) {
		t.Fatalf("a device-wide generate wrote an org slot: %v", err)
	}
}

type failOrgPublicStore struct {
	*testdouble.MemorySecretStore
	account string
}

func (s failOrgPublicStore) Set(service, account, value string) error {
	if account == s.account {
		return errors.New("backend refused the write")
	}
	return s.MemorySecretStore.Set(service, account, value)
}

// A failure between the two writes leaves no half-written org key, and the
// keys already on the device are untouched.
func TestArchiveKeyGenerate_OrgFailureLeavesNoPartialKey(t *testing.T) {
	deps, _, store := newTestDeps(t)
	device := seedActiveArchiveKey(t, deps)
	generateFor(t, deps, testOrgB)
	before := store.Snapshot()

	deps.Store = failOrgPublicStore{store, keychain.OrgArchiveActiveSlot(testOrgA).PublicAccount}
	resp := HandleArchiveKeyGenerate(deps, proto.ArchiveKeyGenerateRequest{OrgID: testOrgA})
	if resp.Success || resp.ErrorCode != string(errs.ErrCodeStorageFailure) {
		t.Fatalf("generate with a failing public write: %+v", resp)
	}
	if !reflect.DeepEqual(before, store.Snapshot()) {
		t.Fatal("a failed org generate left keychain changes behind")
	}
	if pub, _ := keychain.GetArchivePublicKey(store); pub != device.PublicKey {
		t.Fatal("device-wide key changed")
	}
}

func TestArchiveKeyGenerate_RefusesMalformedOrgID(t *testing.T) {
	deps, _, store := newTestDeps(t)
	before := store.Snapshot()
	resp := HandleArchiveKeyGenerate(deps, proto.ArchiveKeyGenerateRequest{OrgID: "not-a-uuid"})
	if resp.Success || resp.ErrorCode != string(errs.ErrCodeValidation) || strings.Contains(resp.Error, "BEGIN") {
		t.Fatalf("malformed org_id: %+v", resp)
	}
	if !reflect.DeepEqual(before, store.Snapshot()) {
		t.Fatal("a refused generate changed the keychain")
	}
}

// Before lv96 every org created or enabled on one device registered the
// device-wide key (generate without org_id is idempotent), so several orgs
// share one private key; status for each such org reports that one key with
// scope "device". This pins that fact for the migration proposal (lv96 b).
func TestArchiveKeyGenerate_DeviceWideKeyIsSharedByOrgsWithoutTheirOwn(t *testing.T) {
	deps, _, _ := newTestDeps(t)
	first := seedActiveArchiveKey(t, deps)  // org A created on this device
	second := seedActiveArchiveKey(t, deps) // org B created on this device
	if first != second {
		t.Fatal("device-wide generate is not idempotent")
	}
	for _, org := range []string{testOrgA, testOrgB} {
		st := HandleArchiveKeyStatus(deps, proto.ArchiveKeyStatusRequest{OrgID: org}).Data.(proto.ArchiveKeyStatusResponseData)
		if st.Scope != keychain.ArchiveScopeDevice || st.Fingerprint != first.Fingerprint {
			t.Fatalf("org %s status: %+v", org, st)
		}
	}
}

// pausingStore holds the first write to account until release is closed, so a
// second generate can run while the first is between its two writes.
type pausingStore struct {
	*testdouble.MemorySecretStore
	account string
	once    sync.Once
	paused  chan struct{}
	release chan struct{}
}

func (s *pausingStore) Set(service, account, value string) error {
	if account == s.account {
		first := false
		s.once.Do(func() { first = true })
		if first {
			close(s.paused)
			<-s.release
		}
	}
	return s.MemorySecretStore.Set(service, account, value)
}

// Two generates for one org interleave at either write. They must leave one
// key pair whose halves match, and both callers must get its public key.
func TestArchiveKeyGenerate_ConcurrentCallsForOneOrgLeaveOneMatchingPair(t *testing.T) {
	slot := keychain.OrgArchiveActiveSlot(testOrgA)
	for name, account := range map[string]string{"pause at private write": slot.PrivateAccount, "pause at public write": slot.PublicAccount} {
		t.Run(name, func(t *testing.T) {
			deps, _, mem := newTestDeps(t)
			store := &pausingStore{MemorySecretStore: mem, account: account, paused: make(chan struct{}), release: make(chan struct{})}
			deps.Store = store
			results := make(chan proto.BaseResponse, 2)
			go func() { results <- HandleArchiveKeyGenerate(deps, proto.ArchiveKeyGenerateRequest{OrgID: testOrgA}) }()
			<-store.paused
			go func() { results <- HandleArchiveKeyGenerate(deps, proto.ArchiveKeyGenerateRequest{OrgID: testOrgA}) }()
			// Give the second caller every chance to interleave before the
			// first one finishes its write.
			select {
			case r := <-results:
				close(store.release)
				results <- r
			case <-time.After(300 * time.Millisecond):
				close(store.release)
			}
			a, b := <-results, <-results
			if !a.Success || !b.Success {
				t.Fatalf("generate: %+v / %+v", a, b)
			}
			pa := a.Data.(proto.ArchiveKeyGenerateResponseData).PublicKey
			pb := b.Data.(proto.ArchiveKeyGenerateResponseData).PublicKey
			if pa != pb {
				t.Fatal("the two callers got different public keys")
			}
			priv, _ := slot.GetPrivate(mem)
			pub, _ := slot.GetPublic(mem)
			parsed, err := crypto.ParsePrivateKey(priv)
			if err != nil {
				t.Fatalf("stored private key: %v", err)
			}
			derived, _ := crypto.PublicKeyToPEM(&parsed.PublicKey)
			if derived != pub || pub != pa {
				t.Fatal("the stored private and public halves do not match the answered key")
			}
		})
	}
}

// A slot left half-written (a private key without its public key, as an
// interrupted commit or generate can leave) is refused, not overwritten.
func TestArchiveKeyGenerate_RefusesPrivateWithoutPublic(t *testing.T) {
	deps, _, store := newTestDeps(t)
	slot := keychain.OrgArchiveActiveSlot(testOrgA)
	if err := slot.SavePrivate(store, "-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----\n"); err != nil {
		t.Fatal(err)
	}
	before := store.Snapshot()
	resp := HandleArchiveKeyGenerate(deps, proto.ArchiveKeyGenerateRequest{OrgID: testOrgA})
	if resp.Success || resp.ErrorCode != string(errs.ErrCodeArchiveKeySlotIncomplete) {
		t.Fatalf("private-only org slot: %+v", resp)
	}
	if !reflect.DeepEqual(before, store.Snapshot()) {
		t.Fatal("a refused generate changed the keychain")
	}
}

// An org rotation in progress owns the org's slots until it commits or
// aborts; a generate must not replace the key it is re-wrapping from.
func TestArchiveKeyGenerate_RefusesWhileOrgRotationIsStaged(t *testing.T) {
	deps, _, store := newTestDeps(t)
	generateFor(t, deps, testOrgA)
	beginOrg(t, deps, testOrgA)
	before := store.Snapshot()
	resp := HandleArchiveKeyGenerate(deps, proto.ArchiveKeyGenerateRequest{OrgID: testOrgA})
	if resp.Success || resp.ErrorCode != string(errs.ErrCodeArchiveKeyRotationPending) {
		t.Fatalf("generate during a staged rotation: %+v", resp)
	}
	if !reflect.DeepEqual(before, store.Snapshot()) {
		t.Fatal("a refused generate changed the keychain")
	}
}

// After a split finalized, the org keeps only the public half. That is not a
// usable key: generate reports the state and creates nothing.
func TestArchiveKeyGenerate_ReportsPublicOnlyOrgKey(t *testing.T) {
	deps, _, store := newTestDeps(t)
	generateFor(t, deps, testOrgA)
	if err := keychain.OrgArchiveActiveSlot(testOrgA).DeletePrivate(store); err != nil {
		t.Fatal(err)
	}
	before := store.Snapshot()
	resp := HandleArchiveKeyGenerate(deps, proto.ArchiveKeyGenerateRequest{OrgID: testOrgA})
	if resp.Success || resp.ErrorCode != string(errs.ErrCodeArchiveKeyPrivateAbsent) || resp.Data != nil {
		t.Fatalf("public-only org slot: %+v", resp)
	}
	if !reflect.DeepEqual(before, store.Snapshot()) {
		t.Fatal("a refused generate changed the keychain")
	}
}
