// device_identity_test.go — device_id_ensure, account_binding_set,
// device_account_status, device_signout.
//
// Defects these tests catch:
//   - an ensure that replaces a stored id, or moves away from the id an MLS
//     leaf record was declared for
//   - two concurrent ensures storing two ids
//   - a candidate that is not a lowercase UUID being adopted
//   - a status or sign-out answer, error or log line carrying key material
//   - a sign-out that removes more than the device master (Q3)
//   - a binding change that a poller of `generation` cannot see
package handlers

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/dragpass/keeper/config"
	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/testdouble"
)

const (
	identityTestCandidate = "33333333-3333-4333-8333-333333333333"
	identityTestOther     = "55555555-5555-4555-8555-555555555555"
	identityTestAlias     = "alice"
)

func ensureDeviceID(t *testing.T, deps Deps, candidate string) proto.DeviceIDEnsureResponseData {
	t.Helper()
	resp := HandleDeviceIDEnsure(deps, proto.DeviceIDEnsureRequest{CandidateDeviceID: candidate})
	if !resp.Success {
		t.Fatalf("device_id_ensure: %s", resp.Error)
	}
	return resp.Data.(proto.DeviceIDEnsureResponseData)
}

func deviceStatus(t *testing.T, deps Deps) proto.DeviceAccountStatusResponseData {
	t.Helper()
	resp := HandleDeviceAccountStatus(deps, proto.DeviceAccountStatusRequest{})
	if !resp.Success {
		t.Fatalf("device_account_status: %s", resp.Error)
	}
	return resp.Data.(proto.DeviceAccountStatusResponseData)
}

// saveLeafFor stores an active MLS leaf record naming deviceID.
func saveLeafFor(t *testing.T, store keychain.SecretStore, deviceID string, active bool) {
	t.Helper()
	public, secret, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	key := keychain.MLSLeafKey{
		AccountID: leafTestAccountID, DeviceID: deviceID,
		SecretKey: secret, PublicKey: public, Declaration: []byte("declaration"),
	}
	save := keychain.SaveMLSLeafPending
	if active {
		save = keychain.SaveMLSLeafKey
	}
	if err := save(store, key); err != nil {
		t.Fatal(err)
	}
}

func assertNoSecretsIn(t *testing.T, log *testdouble.MemoryLogger, resp proto.BaseResponse, secrets ...string) {
	t.Helper()
	encoded, err := json.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range secrets {
		if secret == "" {
			continue
		}
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("response carries a secret: %s", encoded)
		}
		if log.Contains(secret) {
			t.Fatalf("logger leaked a secret: %v", log.Messages())
		}
	}
}

func TestDeviceIDEnsure_GeneratesOnceAndKeepsIt(t *testing.T) {
	deps, _, store := newTestDeps(t)
	first := ensureDeviceID(t, deps, "")
	if first.Source != "generated" || !keychain.ValidDeviceID(first.DeviceID) {
		t.Fatalf("first ensure = %+v", first)
	}
	again := ensureDeviceID(t, deps, identityTestCandidate)
	if again.Source != "stored" || again.DeviceID != first.DeviceID {
		t.Fatalf("a later ensure with a candidate = %+v, want the stored id", again)
	}
	if id, _, _ := keychain.GetDeviceID(store); id != first.DeviceID {
		t.Fatalf("stored id = %q", id)
	}
}

func TestDeviceIDEnsure_AdoptsTheCandidateOnAFreshDevice(t *testing.T) {
	deps, _, _ := newTestDeps(t)
	got := ensureDeviceID(t, deps, identityTestCandidate)
	if got.Source != "candidate" || got.DeviceID != identityTestCandidate {
		t.Fatalf("ensure = %+v", got)
	}
}

// The leaf was declared for one id; adopting another would force a leaf
// replacement and a handover for nothing.
func TestDeviceIDEnsure_AdoptsTheActiveLeafOverTheCandidate(t *testing.T) {
	deps, _, store := newTestDeps(t)
	saveLeafFor(t, store, leafTestDeviceID, true)
	saveLeafFor(t, store, identityTestOther, false)
	got := ensureDeviceID(t, deps, identityTestCandidate)
	if got.Source != "leaf" || got.DeviceID != leafTestDeviceID {
		t.Fatalf("ensure = %+v, want the active leaf's id", got)
	}
}

func TestDeviceIDEnsure_AdoptsAPendingLeaf(t *testing.T) {
	deps, _, store := newTestDeps(t)
	seedActiveKeypairForRotateTest(t, store)
	declareLeaf(t, deps, leafDeclareRequest(proto.MLSLeafReasonEnroll))
	got := ensureDeviceID(t, deps, identityTestCandidate)
	if got.Source != "leaf" || got.DeviceID != leafTestDeviceID {
		t.Fatalf("ensure = %+v, want the pending leaf's id", got)
	}
}

// An unreadable leaf names an id nobody can read; choosing another one could
// strand it, so the ensure refuses and writes nothing.
func TestDeviceIDEnsure_RefusesAnUnreadableLeaf(t *testing.T) {
	deps, log, store := newTestDeps(t)
	const garbage = "not a leaf record SECRET_LEAF_BYTES"
	if err := store.Set(config.Service, config.MLSLeafSignatureKey, garbage); err != nil {
		t.Fatal(err)
	}
	resp := HandleDeviceIDEnsure(deps, proto.DeviceIDEnsureRequest{CandidateDeviceID: identityTestCandidate})
	if resp.Success || resp.ErrorCode != string(errs.ErrCodeStorageFailure) {
		t.Fatalf("ensure = %+v, want storage_failure", resp)
	}
	if _, found, _ := keychain.GetDeviceID(store); found {
		t.Fatal("a refused ensure stored an id")
	}
	assertNoSecretsIn(t, log, resp, "SECRET_LEAF_BYTES")
}

func TestDeviceIDEnsure_RefusesAMalformedStoredIDAndLeavesIt(t *testing.T) {
	deps, log, store := newTestDeps(t)
	const malformed = "NOT-A-UUID-DO-NOT-ECHO"
	if err := store.Set(config.Service, config.DeviceID, malformed); err != nil {
		t.Fatal(err)
	}
	resp := HandleDeviceIDEnsure(deps, proto.DeviceIDEnsureRequest{})
	if resp.Success || resp.ErrorCode != string(errs.ErrCodeStorageFailure) {
		t.Fatalf("ensure = %+v, want storage_failure", resp)
	}
	if got, _ := store.Get(config.Service, config.DeviceID); got != malformed {
		t.Fatal("ensure replaced a malformed stored id")
	}
	assertNoSecretsIn(t, log, resp, malformed)
}

func TestDeviceIDEnsureRequest_RefusesACandidateThatIsNotALowercaseUUID(t *testing.T) {
	for _, candidate := range []string{
		"not-a-uuid",
		"33333333-3333-4333-8333-33333333333",
		"33333333-3333-4333-8333-3333333333333",
		"33333333-3333-4333-8333-33333333333G",
		"33333333-3333-4333-8333-33333333333A",
		"00000000-0000-0000-0000-000000000000",
		"333333333333-4333-8333-3333-33333333",
	} {
		req := proto.DeviceIDEnsureRequest{CandidateDeviceID: candidate}
		if err := req.Validate(); err == nil {
			t.Errorf("candidate %q accepted", candidate)
		}
	}
	if err := (&proto.DeviceIDEnsureRequest{}).Validate(); err != nil {
		t.Fatalf("an absent candidate: %v", err)
	}
}

func TestDeviceIDEnsure_RandomFailureStoresNothing(t *testing.T) {
	deps, _, store := newTestDeps(t)
	deps.Rand = failingReader{}
	resp := HandleDeviceIDEnsure(deps, proto.DeviceIDEnsureRequest{})
	if resp.Success || resp.ErrorCode != string(errs.ErrCodeInternal) {
		t.Fatalf("ensure = %+v, want internal_error", resp)
	}
	if _, found, _ := keychain.GetDeviceID(store); found {
		t.Fatal("a failed generation stored an id")
	}
}

func TestDeviceIDEnsure_ConcurrentCallsStoreOneID(t *testing.T) {
	deps, _, store := newTestDeps(t)
	const callers = 16
	var wg sync.WaitGroup
	results := make(chan proto.DeviceIDEnsureResponseData, callers)
	for i := range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			candidate := ""
			if i%2 == 1 {
				candidate = identityTestCandidate
			}
			resp := HandleDeviceIDEnsure(deps, proto.DeviceIDEnsureRequest{CandidateDeviceID: candidate})
			if resp.Success {
				results <- resp.Data.(proto.DeviceIDEnsureResponseData)
			}
		}()
	}
	wg.Wait()
	close(results)
	stored, _, _ := keychain.GetDeviceID(store)
	chosen := 0
	for got := range results {
		if got.DeviceID != stored {
			t.Fatalf("a caller got %q, stored is %q", got.DeviceID, stored)
		}
		if got.Source != "stored" {
			chosen++
		}
	}
	if chosen != 1 {
		t.Fatalf("%d callers chose an id, want 1", chosen)
	}
}

func TestAccountBindingSet_RequiresAnActiveAccountKey(t *testing.T) {
	deps, _, store := newTestDeps(t)
	resp := HandleAccountBindingSet(deps, proto.AccountBindingSetRequest{AccountID: leafTestAccountID, Alias: identityTestAlias})
	if resp.Success || resp.ErrorCode != string(errs.ErrCodeNotFound) {
		t.Fatalf("binding without an account key = %+v, want not_found", resp)
	}
	if _, found, _ := keychain.GetAccountBinding(store); found {
		t.Fatal("a refused binding was stored")
	}
}

func TestAccountBindingSet_BumpsGenerationOnlyOnChange(t *testing.T) {
	deps, _, store := newTestDeps(t)
	seedActiveKeypairForRotateTest(t, store)
	set := func(account, alias string) proto.AccountBindingSetResponseData {
		t.Helper()
		resp := HandleAccountBindingSet(deps, proto.AccountBindingSetRequest{AccountID: account, Alias: alias})
		if !resp.Success {
			t.Fatalf("binding: %s", resp.Error)
		}
		return resp.Data.(proto.AccountBindingSetResponseData)
	}
	if got := set(leafTestAccountID, identityTestAlias); !got.Changed || got.Generation != 1 {
		t.Fatalf("first set = %+v", got)
	}
	if got := set(leafTestAccountID, identityTestAlias); got.Changed || got.Generation != 1 {
		t.Fatalf("same set = %+v, want unchanged", got)
	}
	if got := set(identityTestOther, "bob"); !got.Changed || got.Generation != 2 {
		t.Fatalf("other account = %+v", got)
	}
	status := deviceStatus(t, deps)
	if status.AccountID != identityTestOther || status.Alias != "bob" || status.Generation != 2 || status.SignedOut {
		t.Fatalf("status = %+v", status)
	}
}

// A sign-in, signup or recovery the App just completed is a change the
// Extension must see even when the record already names the same account:
// a recovery rotates the account key, and a fresh sign-in re-registers a
// revoked device. Only an idempotent rewrite (a restored session) leaves
// the generation alone.
func TestAccountBindingSet_RenewBumpsGenerationOnIdenticalRecord(t *testing.T) {
	deps, _, store := newTestDeps(t)
	seedActiveKeypairForRotateTest(t, store)
	set := func(renew bool) proto.AccountBindingSetResponseData {
		t.Helper()
		resp := HandleAccountBindingSet(deps, proto.AccountBindingSetRequest{
			AccountID: leafTestAccountID, Alias: identityTestAlias, Renew: renew,
		})
		if !resp.Success {
			t.Fatalf("binding: %s", resp.Error)
		}
		return resp.Data.(proto.AccountBindingSetResponseData)
	}
	if got := set(true); !got.Changed || got.Generation != 1 {
		t.Fatalf("first renew = %+v", got)
	}
	if got := set(true); !got.Changed || got.Generation != 2 {
		t.Fatalf("renew of the same record = %+v, want generation 2", got)
	}
	if got := set(false); got.Changed || got.Generation != 2 {
		t.Fatalf("restore of the same record = %+v, want unchanged", got)
	}
	status := deviceStatus(t, deps)
	if status.AccountID != leafTestAccountID || status.Alias != identityTestAlias || status.Generation != 2 || status.SignedOut {
		t.Fatalf("status = %+v", status)
	}
}

func TestAccountBindingSetRequest_Validates(t *testing.T) {
	good := proto.AccountBindingSetRequest{AccountID: leafTestAccountID, Alias: "gh_abcdefghijklmnopqrst"}
	if err := good.Validate(); err != nil {
		t.Fatalf("hidden GitHub alias refused: %v", err)
	}
	for _, bad := range []proto.AccountBindingSetRequest{
		{AccountID: "", Alias: identityTestAlias},
		{AccountID: "11111111-1111-4111-8111-11111111111A", Alias: identityTestAlias},
		{AccountID: leafTestAccountID, Alias: ""},
		{AccountID: leafTestAccountID, Alias: "ab"},
		{AccountID: leafTestAccountID, Alias: "Alice"},
		{AccountID: leafTestAccountID, Alias: "1alice"},
		{AccountID: leafTestAccountID, Alias: "alice bob"},
		{AccountID: leafTestAccountID, Alias: strings.Repeat("a", 33)},
	} {
		if err := bad.Validate(); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}

// The status carries the public key's fingerprint and nothing that opens
// anything: no PEM, no device key, no wrapped DEK.
func TestDeviceAccountStatus_ReportsWithoutKeyMaterial(t *testing.T) {
	deps, log, store := newTestDeps(t)
	seedActiveKeypairForRotateTest(t, store)
	if err := keychain.SaveDeviceKey(store, deviceKeySentinelB64); err != nil {
		t.Fatal(err)
	}
	const wrapped = "WRAPPED_DEVICE_MASTER_SENTINEL"
	if err := keychain.SavePersonalDeviceWrappedDEK(store, wrapped); err != nil {
		t.Fatal(err)
	}
	ensureDeviceID(t, deps, identityTestCandidate)
	if resp := HandleAccountBindingSet(deps, proto.AccountBindingSetRequest{AccountID: leafTestAccountID, Alias: identityTestAlias}); !resp.Success {
		t.Fatal(resp.Error)
	}

	resp := HandleDeviceAccountStatus(deps, proto.DeviceAccountStatusRequest{})
	if !resp.Success {
		t.Fatal(resp.Error)
	}
	got := resp.Data.(proto.DeviceAccountStatusResponseData)
	publicKey, _ := keychain.GetPublicKey(store)
	privateKey, _ := keychain.GetPrivateKey(store)
	want := proto.DeviceAccountStatusResponseData{
		DeviceID: identityTestCandidate, AccountID: leafTestAccountID, Alias: identityTestAlias, Generation: 1,
		AccountKeyFingerprint: crypto.AccountKeyFingerprint([]byte(publicKey)), DeviceMasterPresent: true,
	}
	if got != want {
		t.Fatalf("status = %+v, want %+v", got, want)
	}
	assertNoSecretsIn(t, log, resp, deviceKeySentinelB64, wrapped, privateKey, publicKey)
}

func TestDeviceAccountStatus_EmptyDeviceWritesNothing(t *testing.T) {
	deps, _, store := newTestDeps(t)
	before := store.Snapshot()
	got := deviceStatus(t, deps)
	if got != (proto.DeviceAccountStatusResponseData{}) {
		t.Fatalf("status on an empty keychain = %+v", got)
	}
	if !mapsEqual(before, store.Snapshot()) {
		t.Fatal("status wrote to the keychain")
	}
}

// A wrapped DEK whose device key is gone (the App's device forget) cannot open
// a personal token, so it is no device master.
func TestDeviceAccountStatus_WrappedDEKWithoutDeviceKeyIsNoDeviceMaster(t *testing.T) {
	deps, _, store := newTestDeps(t)
	if err := keychain.SavePersonalDeviceWrappedDEK(store, "wrapped"); err != nil {
		t.Fatal(err)
	}
	if deviceStatus(t, deps).DeviceMasterPresent {
		t.Fatal("device_master_present without a device key")
	}
}

func TestDeviceAccountStatus_MalformedBindingIsStorageFailure(t *testing.T) {
	deps, log, store := newTestDeps(t)
	const malformed = `{"v":9,"alias":"SECRET_BINDING_TEXT"}`
	if err := store.Set(config.Service, config.AccountBinding, malformed); err != nil {
		t.Fatal(err)
	}
	resp := HandleDeviceAccountStatus(deps, proto.DeviceAccountStatusRequest{})
	if resp.Success || resp.ErrorCode != string(errs.ErrCodeStorageFailure) {
		t.Fatalf("status = %+v, want storage_failure", resp)
	}
	assertNoSecretsIn(t, log, resp, "SECRET_BINDING_TEXT")
}

// Q3: the sign-out removes the device master and nothing else, and closes the
// group session handles this process holds.
func TestDeviceSignout_RemovesOnlyTheDeviceMaster(t *testing.T) {
	deps, log, store := newTestDeps(t)
	seedActiveKeypairForRotateTest(t, store)
	if err := keychain.SaveDeviceKey(store, deviceKeySentinelB64); err != nil {
		t.Fatal(err)
	}
	const wrapped = "WRAPPED_DEVICE_MASTER_SENTINEL"
	if err := keychain.SavePersonalDeviceWrappedDEK(store, wrapped); err != nil {
		t.Fatal(err)
	}
	saveLeafFor(t, store, leafTestDeviceID, true)
	ensureDeviceID(t, deps, "")
	if resp := HandleAccountBindingSet(deps, proto.AccountBindingSetRequest{AccountID: leafTestAccountID, Alias: identityTestAlias}); !resp.Success {
		t.Fatal(resp.Error)
	}
	handle, _, err := deps.GroupSessions.Open(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	before := store.Snapshot()

	resp := HandleDeviceSignout(deps, proto.DeviceSignoutRequest{})
	if !resp.Success {
		t.Fatal(resp.Error)
	}
	got := resp.Data.(proto.DeviceSignoutResponseData)
	if !got.DeviceMasterRemoved || got.ClosedGroupSessions != 1 || got.Generation != 2 {
		t.Fatalf("signout = %+v", got)
	}
	if err := deps.GroupSessions.Use(handle, func([]byte) error { return nil }); err == nil {
		t.Fatal("a group session handle survived the sign-out")
	}
	after := store.Snapshot()
	for slot := range before {
		switch slot {
		case config.Service + "|" + config.PersonalDeviceWrappedDEK:
			if _, ok := after[slot]; ok {
				t.Fatal("the device master survived the sign-out")
			}
		case config.Service + "|" + config.AccountBinding:
		default:
			if after[slot] != before[slot] {
				t.Fatalf("the sign-out touched %s", slot)
			}
		}
	}
	status := deviceStatus(t, deps)
	if !status.SignedOut || status.DeviceMasterPresent || status.AccountID != leafTestAccountID || status.AccountKeyFingerprint == "" {
		t.Fatalf("status after sign-out = %+v", status)
	}
	privateKey, _ := keychain.GetPrivateKey(store)
	assertNoSecretsIn(t, log, resp, deviceKeySentinelB64, wrapped, privateKey)

	// The App's next sign-in writes the binding again, which signs back in.
	again := HandleAccountBindingSet(deps, proto.AccountBindingSetRequest{AccountID: leafTestAccountID, Alias: identityTestAlias})
	if !again.Success || !again.Data.(proto.AccountBindingSetResponseData).Changed {
		t.Fatalf("binding after sign-out = %+v", again)
	}
	if status := deviceStatus(t, deps); status.SignedOut || status.Generation != 3 {
		t.Fatalf("status after the next sign-in = %+v", status)
	}
}

func TestDeviceSignout_IsIdempotentAndWorksWithoutABinding(t *testing.T) {
	deps, _, _ := newTestDeps(t)
	first := HandleDeviceSignout(deps, proto.DeviceSignoutRequest{})
	if !first.Success || first.Data.(proto.DeviceSignoutResponseData).DeviceMasterRemoved {
		t.Fatalf("first = %+v", first)
	}
	second := HandleDeviceSignout(deps, proto.DeviceSignoutRequest{})
	if !second.Success {
		t.Fatal(second.Error)
	}
	if a, b := first.Data.(proto.DeviceSignoutResponseData).Generation, second.Data.(proto.DeviceSignoutResponseData).Generation; a != 1 || b != 1 {
		t.Fatalf("generations %d then %d, want 1 and 1", a, b)
	}
	if status := deviceStatus(t, deps); !status.SignedOut || status.AccountID != "" {
		t.Fatalf("status = %+v", status)
	}
}

type failingDeleteStore struct{ *testdouble.MemorySecretStore }

func (failingDeleteStore) Delete(string, string) error {
	return errors.New("backend refused " + deviceKeySentinelB64)
}

func TestDeviceSignout_StoreErrorTextIsNotEchoed(t *testing.T) {
	deps, log, store := newTestDeps(t)
	if err := keychain.SavePersonalDeviceWrappedDEK(store, "wrapped"); err != nil {
		t.Fatal(err)
	}
	deps.Store = failingDeleteStore{store}
	resp := HandleDeviceSignout(deps, proto.DeviceSignoutRequest{})
	if resp.Success || resp.ErrorCode != string(errs.ErrCodeStorageFailure) {
		t.Fatalf("signout = %+v, want storage_failure", resp)
	}
	if binding, _, _ := keychain.GetAccountBinding(store); binding.SignedOut {
		t.Fatal("a failed sign-out marked the binding signed out")
	}
	assertNoSecretsIn(t, log, resp, deviceKeySentinelB64)
}

func TestResetDeviceIdentity_ClearsDeviceIDAndBinding(t *testing.T) {
	deps, _, store := newTestDeps(t)
	seedActiveKeypairForRotateTest(t, store)
	first := ensureDeviceID(t, deps, "")
	if resp := HandleAccountBindingSet(deps, proto.AccountBindingSetRequest{AccountID: leafTestAccountID, Alias: identityTestAlias}); !resp.Success {
		t.Fatal(resp.Error)
	}
	resp := HandleResetDeviceIdentity(deps, proto.ResetDeviceIdentityRequest{})
	if !resp.Success {
		t.Fatal(resp.Error)
	}
	cleared := strings.Join(resp.Data.(proto.ResetDeviceIdentityResponseData).Cleared, ",")
	if !strings.Contains(cleared, config.DeviceID) || !strings.Contains(cleared, config.AccountBinding) {
		t.Fatalf("cleared = %s", cleared)
	}
	if status := deviceStatus(t, deps); status != (proto.DeviceAccountStatusResponseData{}) {
		t.Fatalf("status after reset = %+v", status)
	}
	if next := ensureDeviceID(t, deps, ""); next.Source != "generated" || next.DeviceID == first.DeviceID {
		t.Fatalf("ensure after reset = %+v", next)
	}
}

func mapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}
