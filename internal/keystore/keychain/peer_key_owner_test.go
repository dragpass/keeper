// peer_key_owner_test.go — the recorded pin owner slot.
//
// Runs against MemorySecretStore through the same interface the platform
// keyring is reached by, like every other slot in this package.

package keychain

import (
	"encoding/json"
	"testing"

	"github.com/dragpass/keeper/config"
)

const (
	ownerAccountOne = "11111111-1111-4111-8111-111111111111"
	ownerAccountTwo = "22222222-2222-4222-8222-222222222222"
)

func TestPeerKeyOwner_AbsentIsNotAnError(t *testing.T) {
	store := NewMemorySecretStore()

	owner, found, err := GetPeerKeyOwner(store)
	if err != nil {
		t.Fatalf("GetPeerKeyOwner on an empty store: %v", err)
	}
	if found || owner.AccountID != "" {
		t.Fatalf("empty store reported owner %+v found=%t, want none", owner, found)
	}
}

func TestPeerKeyOwner_SaveGetDelete(t *testing.T) {
	store := NewMemorySecretStore()

	if err := SavePeerKeyOwner(store, ownerAccountOne, 1758240000); err != nil {
		t.Fatalf("SavePeerKeyOwner: %v", err)
	}

	owner, found, err := GetPeerKeyOwner(store)
	if err != nil || !found {
		t.Fatalf("GetPeerKeyOwner after save: found=%t err=%v", found, err)
	}
	if owner.AccountID != ownerAccountOne || owner.RecordedAt != 1758240000 {
		t.Fatalf("owner = %+v, want the saved record", owner)
	}
	if owner.V != PeerKeyOwnerVersion {
		t.Fatalf("v = %d, want %d", owner.V, PeerKeyOwnerVersion)
	}

	deleted, err := DeletePeerKeyOwner(store)
	if err != nil || !deleted {
		t.Fatalf("DeletePeerKeyOwner: deleted=%t err=%v", deleted, err)
	}
	if _, found, err := GetPeerKeyOwner(store); err != nil || found {
		t.Fatalf("owner survived the delete: found=%t err=%v", found, err)
	}

	// Idempotent.
	deleted, err = DeletePeerKeyOwner(store)
	if err != nil || deleted {
		t.Fatalf("second delete: deleted=%t err=%v, want false/nil", deleted, err)
	}
}

// The record replaces rather than accumulating: there is one owner at a time.
func TestPeerKeyOwner_SaveReplaces(t *testing.T) {
	store := NewMemorySecretStore()

	if err := SavePeerKeyOwner(store, ownerAccountOne, 1); err != nil {
		t.Fatalf("SavePeerKeyOwner one: %v", err)
	}
	if err := SavePeerKeyOwner(store, ownerAccountTwo, 2); err != nil {
		t.Fatalf("SavePeerKeyOwner two: %v", err)
	}

	owner, _, err := GetPeerKeyOwner(store)
	if err != nil {
		t.Fatalf("GetPeerKeyOwner: %v", err)
	}
	if owner.AccountID != ownerAccountTwo {
		t.Fatalf("owner = %q, want the most recent save", owner.AccountID)
	}
}

// An unreadable record is an error rather than a quiet "no owner recorded".
// Falling back would hand the next request whatever namespace it asked for,
// which is the move the slot exists to refuse.
func TestPeerKeyOwner_UnreadableRecordIsAnError(t *testing.T) {
	for _, raw := range []string{"not json at all", `{"v":1,"account_id":""}`} {
		store := NewMemorySecretStore()
		if err := store.Set(config.Service, config.PeerKeyOwnerAccount, raw); err != nil {
			t.Fatalf("Set: %v", err)
		}
		if _, found, err := GetPeerKeyOwner(store); err == nil || found {
			t.Fatalf("record %q gave found=%t err=%v, want an error", raw, found, err)
		}
	}
}

// One entry, no owner in the name — it is the thing that decides what "owner"
// means, so it cannot be scoped by one.
func TestPeerKeyOwner_IsASingleUnscopedSlot(t *testing.T) {
	store := NewMemorySecretStore()
	if err := SavePeerKeyOwner(store, ownerAccountOne, 1758240000); err != nil {
		t.Fatalf("SavePeerKeyOwner: %v", err)
	}

	raw, err := store.Get(config.Service, config.PeerKeyOwnerAccount)
	if err != nil {
		t.Fatalf("the record is not at config.PeerKeyOwnerAccount: %v", err)
	}
	var decoded PeerKeyOwner
	if err := json.Unmarshal([]byte(raw), &decoded); err != nil {
		t.Fatalf("stored record is not the documented JSON: %v", err)
	}
	if decoded.AccountID != ownerAccountOne {
		t.Fatalf("stored account_id = %q", decoded.AccountID)
	}
}
