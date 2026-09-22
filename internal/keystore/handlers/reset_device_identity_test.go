// reset_device_identity_test.go — regression guard for reset_device_identity.go
// (HandleResetDeviceIdentity).
//
// **Defects this test catches:**
//   - a slot that should be wiped is left behind (or vice versa)
//   - versioned server key state wrongly wiped
//   - the cleared list not matching what was actually present (idempotency)
//   - an empty result serializing as `null` instead of `[]`
//   - key material echoed to the logger / error string
//   - chat state left behind by a reset (the entrance for a rewound chain)
package handlers

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/dragpass/keeper/config"
	"github.com/dragpass/keeper/internal/keystore/chatstate"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/logger"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// newResetDeps is newTestDeps with the chat state root pointed at a temporary
// directory. A reset erases chat state, so a test that skipped this would erase
// the developer's own — which is why chatstate.Root is derived from
// os.UserConfigDir and stays overridable.
func newResetDeps(t *testing.T) (Deps, *logger.MemoryLogger, *keychain.MemorySecretStore) {
	t.Helper()
	t.Setenv(chatstate.RootEnvVar, filepath.Join(t.TempDir(), "chat-state"))
	return newTestDeps(t)
}

// seedAllIdentitySlots writes every account-scoped slot plus the preserved
// server key state, returning sentinel values for log assertions.
func seedAllIdentitySlots(t *testing.T, store keychain.SecretStore) map[string]string {
	t.Helper()
	sentinels := map[string]string{
		config.DragPassKeeperPrivateKey:        "PRIV_KEY_PEM_DO_NOT_LEAK",
		config.DragPassKeeperPublicKey:         "PUB_KEY_PEM_DO_NOT_LEAK",
		config.PendingDragPassKeeperPrivateKey: "PENDING_PRIV_PEM_DO_NOT_LEAK",
		config.PendingDragPassKeeperPublicKey:  "PENDING_PUB_PEM_DO_NOT_LEAK",
		config.SessionCode:                     "SESSION_CODE_DO_NOT_LEAK",
		config.PersonalDeviceWrappedDEK:        "PERSONAL_WRAPPED_DEK_DO_NOT_LEAK",
		config.DeviceKey:                       "DEVICE_KEY_B64_DO_NOT_LEAK",
	}
	save := map[string]func(keychain.SecretStore, string) error{
		config.DragPassKeeperPrivateKey:        keychain.SavePrivateKey,
		config.DragPassKeeperPublicKey:         keychain.SavePublicKey,
		config.PendingDragPassKeeperPrivateKey: keychain.SavePendingPrivateKey,
		config.PendingDragPassKeeperPublicKey:  keychain.SavePendingPublicKey,
		config.SessionCode:                     keychain.SaveSessionCode,
		config.PersonalDeviceWrappedDEK:        keychain.SavePersonalDeviceWrappedDEK,
		config.DeviceKey:                       keychain.SaveDeviceKey,
	}
	for name, fn := range save {
		if err := fn(store, sentinels[name]); err != nil {
			t.Fatalf("test setup: save %s: %v", name, err)
		}
	}
	const serverKey = "SERVER_PUB_PEM_TRUST_ANCHOR"
	if err := keychain.SaveServerPublicKeyForVersion(store, 1, serverKey); err != nil {
		t.Fatalf("test setup: save server key: %v", err)
	}
	if err := keychain.SaveActiveServerKeyVersion(store, 1); err != nil {
		t.Fatalf("test setup: save active server key version: %v", err)
	}
	sentinels[config.DragPassServerPublicKeyVersionedPrefix+"1"] = serverKey
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
	deps, log, store := newResetDeps(t)
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
		config.PersonalDeviceWrappedDEK,
		config.DeviceKey,
	}
	got := clearedList(t, resp)
	assertSameSet(t, want, got)

	for _, name := range want {
		if slotStillPresent(t, store, name) {
			t.Errorf("slot %s should have been cleared but is still present", name)
		}
	}

	if !slotStillPresent(t, store, config.DragPassServerPublicKeyVersionedPrefix+"1") {
		t.Errorf("versioned server public key must be preserved but was wiped")
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
	deps, _, store := newResetDeps(t)

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
	deps, _, store := newResetDeps(t)

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

// TestResetDeviceIdentity_ErasesChatStateOfEveryOwner: the reset names no
// account, so it has to reach every owner's conversations. What is left behind
// otherwise is a sealed file plus the key that opens it, which is what a
// restored backup needs to put a spent chain position back in play.
func TestResetDeviceIdentity_ErasesChatStateOfEveryOwner(t *testing.T) {
	deps, _, store := newResetDeps(t)
	const (
		ownerA = "11111111-1111-4111-8111-111111111111"
		ownerB = "55555555-5555-4555-8555-555555555555"
	)
	for _, owner := range []string{ownerA, ownerB} {
		state, err := chatstate.Open(store, owner)
		if err != nil {
			t.Fatalf("seed %s: %v", owner, err)
		}
		if _, err := state.Reserve(chatConvID, 1, chatstate.ServerWatermark{}); err != nil {
			t.Fatalf("seed %s: %v", owner, err)
		}
		state.Close()
	}
	root := os.Getenv(chatstate.RootEnvVar)
	if got := ownerDirectoryCount(t, root); got != 2 {
		t.Fatalf("seeding left %d owner directories, want 2", got)
	}

	resp := HandleResetDeviceIdentity(deps, proto.ResetDeviceIdentityRequest{})
	if !resp.Success {
		t.Fatalf("expected success, got error %q", resp.Error)
	}

	if got := ownerDirectoryCount(t, root); got != 0 {
		t.Errorf("%d owner directories survived the reset", got)
	}
	// The seal keys and the anchors go with them, and nothing else was seeded
	// into this store, so an empty keychain is the whole assertion.
	if got := store.Size(); got != 0 {
		t.Errorf("keychain still holds %d entries after the reset", got)
	}
}

// ownerDirectoryCount counts the owner directories under a state root. The
// root also holds the lock file the seal mint takes, which is not one.
func ownerDirectoryCount(t *testing.T, root string) int {
	t.Helper()
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read state root: %v", err)
	}
	count := 0
	for _, entry := range entries {
		if entry.IsDir() {
			count++
		}
	}
	return count
}

// TestResetDeviceIdentity_WithoutAnyChatState_StillSucceeds: the reset runs on
// devices that never opened a conversation, so an absent state root is an
// ordinary success.
func TestResetDeviceIdentity_WithoutAnyChatState_StillSucceeds(t *testing.T) {
	deps, _, _ := newResetDeps(t)
	if _, err := os.Stat(os.Getenv(chatstate.RootEnvVar)); !os.IsNotExist(err) {
		t.Fatalf("the fixture root should not exist yet: %v", err)
	}

	resp := HandleResetDeviceIdentity(deps, proto.ResetDeviceIdentityRequest{})
	if !resp.Success {
		t.Fatalf("expected success on a device with no chat state, got %q", resp.Error)
	}
}

// TestResetDeviceIdentity_LogsProcessing_NoMaterial: the processing log is
// emitted and the count line carries no key material.
func TestResetDeviceIdentity_LogsProcessing_NoMaterial(t *testing.T) {
	deps, log, store := newResetDeps(t)
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
