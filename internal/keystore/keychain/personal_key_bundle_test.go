package keychain

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/dragpass/keeper/config"
)

type failSetOnceStore struct {
	SecretStore
	account string
	failed  bool
}

type failDeleteStore struct {
	SecretStore
	account string
}

type failGetOnceStore struct {
	SecretStore
	account string
	failed  bool
}

func (s *failDeleteStore) Delete(service, account string) error {
	if account == s.account {
		return errors.New("injected delete failure")
	}
	return s.SecretStore.Delete(service, account)
}

func (s *failSetOnceStore) Set(service, account, value string) error {
	if account == s.account && !s.failed {
		s.failed = true
		return errors.New("injected set failure")
	}
	return s.SecretStore.Set(service, account, value)
}

func (s *failGetOnceStore) Get(service, account string) (string, error) {
	if account == s.account && !s.failed {
		s.failed = true
		return "", errors.New("injected get failure")
	}
	return s.SecretStore.Get(service, account)
}

func seedPersonalKeyBundle(t *testing.T, store SecretStore, deviceKey, wrappedDEK string) {
	t.Helper()
	if err := store.Set(config.Service, config.DeviceKey, deviceKey); err != nil {
		t.Fatal(err)
	}
	if err := store.Set(config.Service, config.PersonalDeviceWrappedDEK, wrappedDEK); err != nil {
		t.Fatal(err)
	}
}

func TestCommitPersonalKeyBundleRotation(t *testing.T) {
	store := NewMemorySecretStore()
	seedPersonalKeyBundle(t, store, "old-device", "old-wrapped")

	if err := CommitPersonalKeyBundleRotation(
		store, "old-device", "old-wrapped", "new-device", "new-wrapped",
	); err != nil {
		t.Fatal(err)
	}
	if got, _ := GetDeviceKey(store); got != "new-device" {
		t.Fatalf("device key = %q", got)
	}
	if got, _ := GetPersonalDeviceWrappedDEK(store); got != "new-wrapped" {
		t.Fatalf("wrapped DEK = %q", got)
	}
	if _, err := GetPendingPersonalKeyBundle(store); !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("journal remains: %v", err)
	}
}

func TestCommitPersonalKeyBundleRotationRollsBackPartialWrite(t *testing.T) {
	base := NewMemorySecretStore()
	seedPersonalKeyBundle(t, base, "old-device", "old-wrapped")
	store := &failSetOnceStore{SecretStore: base, account: config.PersonalDeviceWrappedDEK}

	if err := CommitPersonalKeyBundleRotation(
		store, "old-device", "old-wrapped", "new-device", "new-wrapped",
	); err == nil {
		t.Fatal("expected injected failure")
	}
	if got, _ := GetDeviceKey(store); got != "old-device" {
		t.Fatalf("device key after rollback = %q", got)
	}
	if got, _ := GetPersonalDeviceWrappedDEK(store); got != "old-wrapped" {
		t.Fatalf("wrapped DEK after rollback = %q", got)
	}
	if _, err := GetPendingPersonalKeyBundle(store); !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("journal remains after rollback: %v", err)
	}
}

func TestCommitPersonalKeyBundleRotationRejectsStaleWrappedDEK(t *testing.T) {
	store := NewMemorySecretStore()
	seedPersonalKeyBundle(t, store, "old-device", "current-wrapped")

	err := CommitPersonalKeyBundleRotation(
		store, "old-device", "stale-wrapped", "new-device", "new-wrapped",
	)
	if err == nil {
		t.Fatal("expected stale wrapped DEK rejection")
	}
	if got, _ := GetDeviceKey(store); got != "old-device" {
		t.Fatalf("device key changed after rejection: %q", got)
	}
}

func TestCommitPersonalKeyBundleRotationDoesNotFailAfterCommittedCleanupError(t *testing.T) {
	base := NewMemorySecretStore()
	seedPersonalKeyBundle(t, base, "old-device", "old-wrapped")
	store := &failDeleteStore{
		SecretStore: base,
		account:     config.PendingPersonalKeyBundle,
	}

	if err := CommitPersonalKeyBundleRotation(
		store, "old-device", "old-wrapped", "new-device", "new-wrapped",
	); err != nil {
		t.Fatalf("committed rotation failed on journal cleanup: %v", err)
	}
	if got, _ := base.Get(config.Service, config.DeviceKey); got != "new-device" {
		t.Fatalf("committed device key = %q", got)
	}
	if got, _ := base.Get(config.Service, config.PersonalDeviceWrappedDEK); got != "new-wrapped" {
		t.Fatalf("committed wrapped DEK = %q", got)
	}
	if err := SaveDeviceKey(store, "later-device"); !errors.Is(err, errPersonalKeyBundleCleanupPending) {
		t.Fatalf("write with pending cleanup error = %v", err)
	}
	if got, _ := base.Get(config.Service, config.DeviceKey); got != "new-device" {
		t.Fatalf("blocked write changed device key = %q", got)
	}
}

func TestRecoveryDoesNotRollbackOnTransientReadFailure(t *testing.T) {
	base := NewMemorySecretStore()
	seedPersonalKeyBundle(t, base, "new-device", "new-wrapped")
	journal, err := json.Marshal(personalKeyBundleJournal{
		OldDeviceKeyB64: "old-device",
		OldWrappedDEK:   "old-wrapped",
		NewDeviceKeyB64: "new-device",
		NewWrappedDEK:   "new-wrapped",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := base.Set(config.Service, config.PendingPersonalKeyBundle, string(journal)); err != nil {
		t.Fatal(err)
	}
	store := &failGetOnceStore{SecretStore: base, account: config.DeviceKey}

	if _, err := GetDeviceKey(store); err == nil {
		t.Fatal("expected injected read failure")
	}
	if got, _ := base.Get(config.Service, config.DeviceKey); got != "new-device" {
		t.Fatalf("read failure rolled device key back to %q", got)
	}
	if got, _ := base.Get(config.Service, config.PersonalDeviceWrappedDEK); got != "new-wrapped" {
		t.Fatalf("read failure rolled wrapped DEK back to %q", got)
	}
}

func TestRecoveryDoesNotOverwriteUnrelatedBundle(t *testing.T) {
	store := NewMemorySecretStore()
	seedPersonalKeyBundle(t, store, "later-device", "later-wrapped")
	journal, err := json.Marshal(personalKeyBundleJournal{
		OldDeviceKeyB64: "old-device",
		OldWrappedDEK:   "old-wrapped",
		NewDeviceKeyB64: "new-device",
		NewWrappedDEK:   "new-wrapped",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Set(config.Service, config.PendingPersonalKeyBundle, string(journal)); err != nil {
		t.Fatal(err)
	}

	if _, err := GetDeviceKey(store); err == nil {
		t.Fatal("expected unrelated bundle rejection")
	}
	if got, _ := store.Get(config.Service, config.DeviceKey); got != "later-device" {
		t.Fatalf("unrelated device key overwritten with %q", got)
	}
	if got, _ := store.Get(config.Service, config.PersonalDeviceWrappedDEK); got != "later-wrapped" {
		t.Fatalf("unrelated wrapped DEK overwritten with %q", got)
	}
}

func TestGetDeviceKeyRecoversInterruptedPersonalKeyRotation(t *testing.T) {
	store := NewMemorySecretStore()
	seedPersonalKeyBundle(t, store, "new-device", "old-wrapped")
	journal, err := json.Marshal(personalKeyBundleJournal{
		OldDeviceKeyB64: "old-device",
		OldWrappedDEK:   "old-wrapped",
		NewDeviceKeyB64: "new-device",
		NewWrappedDEK:   "new-wrapped",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Set(config.Service, config.PendingPersonalKeyBundle, string(journal)); err != nil {
		t.Fatal(err)
	}

	if got, err := GetDeviceKey(store); err != nil || got != "old-device" {
		t.Fatalf("recovered device key = %q, err = %v", got, err)
	}
	if got, _ := GetPersonalDeviceWrappedDEK(store); got != "old-wrapped" {
		t.Fatalf("recovered wrapped DEK = %q", got)
	}
}

func TestGetDeviceKeyFinalizesCommittedPersonalKeyRotation(t *testing.T) {
	store := NewMemorySecretStore()
	seedPersonalKeyBundle(t, store, "new-device", "new-wrapped")
	journal, err := json.Marshal(personalKeyBundleJournal{
		OldDeviceKeyB64: "old-device",
		OldWrappedDEK:   "old-wrapped",
		NewDeviceKeyB64: "new-device",
		NewWrappedDEK:   "new-wrapped",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Set(config.Service, config.PendingPersonalKeyBundle, string(journal)); err != nil {
		t.Fatal(err)
	}

	if got, err := GetDeviceKey(store); err != nil || got != "new-device" {
		t.Fatalf("finalized device key = %q, err = %v", got, err)
	}
	if _, err := GetPendingPersonalKeyBundle(store); !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("journal remains after finalize: %v", err)
	}
}
