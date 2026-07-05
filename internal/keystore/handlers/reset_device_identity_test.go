// reset_device_identity_test.go — regression guard for reset_device_identity.go
// (HandleResetDeviceIdentity).
//
// **Defects this test catches:**
//   - a slot that should be wiped is left behind (or vice versa)
//   - server_public_key (account-independent trust anchor) wrongly wiped
//   - the cleared list not matching what was actually present (idempotency)
//   - an empty result serializing as `null` instead of `[]`
//   - key material echoed to the logger / error string
package handlers

import (
	"encoding/json"
	"sort"
	"strings"
	"testing"

	"github.com/dragpass/keeper/config"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// seedAllIdentitySlots writes every account-scoped slot plus the preserved
// server_public_key, returning the sentinel values so the caller can assert
// they are not echoed.
func seedAllIdentitySlots(t *testing.T, store keychain.SecretStore) map[string]string {
	t.Helper()
	sentinels := map[string]string{
		config.DragPassKeeperPrivateKey:        "PRIV_KEY_PEM_DO_NOT_LEAK",
		config.DragPassKeeperPublicKey:         "PUB_KEY_PEM_DO_NOT_LEAK",
		config.PendingDragPassKeeperPrivateKey: "PENDING_PRIV_PEM_DO_NOT_LEAK",
		config.PendingDragPassKeeperPublicKey:  "PENDING_PUB_PEM_DO_NOT_LEAK",
		config.SessionCode:                     "SESSION_CODE_DO_NOT_LEAK",
		config.DeviceKey:                       "DEVICE_KEY_B64_DO_NOT_LEAK",
		config.DragPassServerPublicKey:         "SERVER_PUB_PEM_TRUST_ANCHOR",
	}
	save := map[string]func(keychain.SecretStore, string) error{
		config.DragPassKeeperPrivateKey:        keychain.SavePrivateKey,
		config.DragPassKeeperPublicKey:         keychain.SavePublicKey,
		config.PendingDragPassKeeperPrivateKey: keychain.SavePendingPrivateKey,
		config.PendingDragPassKeeperPublicKey:  keychain.SavePendingPublicKey,
		config.SessionCode:                     keychain.SaveSessionCode,
		config.DeviceKey:                       keychain.SaveDeviceKey,
		config.DragPassServerPublicKey:         keychain.SaveServerPublicKey,
	}
	for name, fn := range save {
		if err := fn(store, sentinels[name]); err != nil {
			t.Fatalf("test setup: save %s: %v", name, err)
		}
	}
	return sentinels
}

func clearedList(t *testing.T, resp proto.BaseResponse) []string {
	t.Helper()
	data, ok := resp.Data.(proto.ResetDeviceIdentityResponseData)
	if !ok {
		t.Fatalf("response data is not ResetDeviceIdentityResponseData: %#v", resp.Data)
	}
	return data.Cleared
}

func slotStillPresent(t *testing.T, store keychain.SecretStore, name string) bool {
	t.Helper()
	_, err := store.Get(config.Service, name)
	return err == nil
}

// TestResetDeviceIdentity_AllSlots_ClearsEverythingButServerKey: every
// account-scoped slot is wiped, the cleared list names them all, and
// server_public_key survives.
func TestResetDeviceIdentity_AllSlots_ClearsEverythingButServerKey(t *testing.T) {
	deps, log, store := newTestDeps(t)
	sentinels := seedAllIdentitySlots(t, store)

	resp := HandleResetDeviceIdentity(deps, proto.ResetDeviceIdentityRequest{})
	if !resp.Success {
		t.Fatalf("expected success, got error %q", resp.Error)
	}

	want := []string{
		config.DragPassKeeperPrivateKey,
		config.DragPassKeeperPublicKey,
		config.PendingDragPassKeeperPrivateKey,
		config.PendingDragPassKeeperPublicKey,
		config.SessionCode,
		config.DeviceKey,
	}
	got := clearedList(t, resp)
	assertSameSet(t, want, got)

	for _, name := range want {
		if slotStillPresent(t, store, name) {
			t.Errorf("slot %s should have been cleared but is still present", name)
		}
	}

	// The trust anchor must survive.
	if !slotStillPresent(t, store, config.DragPassServerPublicKey) {
		t.Errorf("server_public_key must be preserved but was wiped")
	}

	// No key material may appear in the log.
	for name, val := range sentinels {
		if log.Contains(val) {
			t.Errorf("logger leaked %s material: %v", name, log.Messages())
		}
	}
}

// TestResetDeviceIdentity_PartialSlots_ReportsOnlyPresent: only present slots
// appear in the cleared list.
func TestResetDeviceIdentity_PartialSlots_ReportsOnlyPresent(t *testing.T) {
	deps, _, store := newTestDeps(t)

	if err := keychain.SavePrivateKey(store, "PRIV"); err != nil {
		t.Fatalf("setup: %v", err)
	}
	if err := keychain.SaveSessionCode(store, "SESSION"); err != nil {
		t.Fatalf("setup: %v", err)
	}

	resp := HandleResetDeviceIdentity(deps, proto.ResetDeviceIdentityRequest{})
	if !resp.Success {
		t.Fatalf("expected success, got error %q", resp.Error)
	}

	assertSameSet(t, []string{config.DragPassKeeperPrivateKey, config.SessionCode}, clearedList(t, resp))
}

// TestResetDeviceIdentity_Empty_IsIdempotent: an empty keychain still succeeds
// with an empty (non-null) cleared list.
func TestResetDeviceIdentity_Empty_IsIdempotent(t *testing.T) {
	deps, _, store := newTestDeps(t)

	resp := HandleResetDeviceIdentity(deps, proto.ResetDeviceIdentityRequest{})
	if !resp.Success {
		t.Fatalf("expected success on empty keychain, got error %q", resp.Error)
	}
	if got := clearedList(t, resp); len(got) != 0 {
		t.Fatalf("expected empty cleared list, got %v", got)
	}

	// An empty result must serialize as `[]`, never `null` (contract).
	blob, err := json.Marshal(resp.Data)
	if err != nil {
		t.Fatalf("marshal response data: %v", err)
	}
	if !strings.Contains(string(blob), `"cleared":[]`) {
		t.Fatalf("empty cleared must serialize as [], got %s", blob)
	}

	// Idempotent: a second call is also a clean success.
	resp2 := HandleResetDeviceIdentity(deps, proto.ResetDeviceIdentityRequest{})
	if !resp2.Success || len(clearedList(t, resp2)) != 0 {
		t.Fatalf("second reset should also succeed with empty list: %#v", resp2)
	}
	_ = store
}

// TestResetDeviceIdentity_LogsProcessing_NoMaterial: the processing log is
// emitted and the count line carries no key material.
func TestResetDeviceIdentity_LogsProcessing_NoMaterial(t *testing.T) {
	deps, log, store := newTestDeps(t)
	sentinels := seedAllIdentitySlots(t, store)

	_ = HandleResetDeviceIdentity(deps, proto.ResetDeviceIdentityRequest{})

	if !log.Contains("reset device identity request processing") {
		t.Fatalf("expected processing log, got %v", log.Messages())
	}
	for _, val := range sentinels {
		if log.Contains(val) {
			t.Fatalf("logger leaked material: %v", log.Messages())
		}
	}
}

func assertSameSet(t *testing.T, want, got []string) {
	t.Helper()
	w := append([]string(nil), want...)
	g := append([]string(nil), got...)
	sort.Strings(w)
	sort.Strings(g)
	if len(w) != len(g) {
		t.Fatalf("set mismatch: want %v, got %v", w, g)
	}
	for i := range w {
		if w[i] != g[i] {
			t.Fatalf("set mismatch: want %v, got %v", w, g)
		}
	}
}
