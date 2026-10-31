package keychain

import (
	"testing"

	"github.com/dragpass/keeper/config"
	"github.com/zalando/go-keyring"
)

func TestPersonalDEKFirstWriteWithPlatformStore(t *testing.T) {
	keyring.MockInit()
	store := KeyringSecretStore{}
	// A fresh installation has no provenance slot to invalidate.
	if err := savePersonalDeviceWrappedDEKLocked(store, "fixture-wrap"); err != nil {
		t.Fatalf("first personal slot write rejected: %v", err)
	}
	got, err := store.Get(config.Service, config.PersonalDeviceWrappedDEK)
	if err != nil || got != "fixture-wrap" {
		t.Fatal("personal slot was not stored")
	}
}
