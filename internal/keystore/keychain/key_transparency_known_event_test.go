package keychain

import (
	"encoding/hex"
	"errors"
	"testing"

	"github.com/dragpass/keeper/config"
)

func TestKnownKeyTransparencyEvent_IsBoundToAccountAndStatement(t *testing.T) {
	store := NewMemorySecretStore()
	statement := []byte("signed statement")
	accountID := "11111111-1111-4111-8111-111111111111"

	found, err := HasKnownKeyTransparencyEvent(store, accountID, statement)
	if err != nil || found {
		t.Fatalf("initial lookup: found=%t err=%v", found, err)
	}
	pendingID, err := PendingKeyTransparencyEventID([]byte("public key material"))
	if err != nil {
		t.Fatal(err)
	}
	if err := StageKeyTransparencyEvent(store, accountID, pendingID, statement); err != nil {
		t.Fatalf("stage event: %v", err)
	}
	if err := PromoteKeyTransparencyEvent(store, pendingID); err != nil {
		t.Fatalf("promote event: %v", err)
	}
	found, err = HasKnownKeyTransparencyEvent(store, accountID, statement)
	if err != nil || !found {
		t.Fatalf("saved lookup: found=%t err=%v", found, err)
	}
	if found, err := HasKnownKeyTransparencyEvent(store, "22222222-2222-4222-8222-222222222222", statement); err != nil || found {
		t.Fatalf("other account lookup: found=%t err=%v", found, err)
	}
	if found, err := HasKnownKeyTransparencyEvent(store, accountID, []byte("different statement")); err != nil || found {
		t.Fatalf("different statement lookup: found=%t err=%v", found, err)
	}

	digest, err := keyTransparencyEventDigest(accountID, statement)
	if err != nil {
		t.Fatal(err)
	}
	key := config.KeyTransparencyKnownEventPrefix + accountID + ":" + hex.EncodeToString(digest[:])
	if _, err := store.Get(config.Service, key); err != nil {
		t.Fatalf("expected hash-addressed keychain record: %v", err)
	}
}

func TestKnownKeyTransparencyEvent_RejectsInvalidRecordInputs(t *testing.T) {
	store := NewMemorySecretStore()
	for _, tc := range []struct {
		accountID string
		statement []byte
	}{
		{accountID: "not-an-account", statement: []byte("statement")},
		{accountID: "00000000-0000-0000-0000-000000000000", statement: []byte("statement")},
		{accountID: "11111111-1111-4111-8111-111111111111"},
		{accountID: "11111111-1111-4111-8111-111111111111", statement: make([]byte, 64*1024+1)},
	} {
		pendingID, err := PendingKeyTransparencyEventID([]byte("public key material"))
		if err != nil {
			t.Fatal(err)
		}
		if err := StageKeyTransparencyEvent(store, tc.accountID, pendingID, tc.statement); err == nil {
			t.Fatalf("StageKeyTransparencyEvent(%q, %d bytes) succeeded", tc.accountID, len(tc.statement))
		}
		if _, err := HasKnownKeyTransparencyEvent(store, tc.accountID, tc.statement); err == nil {
			t.Fatalf("HasKnownKeyTransparencyEvent(%q, %d bytes) succeeded", tc.accountID, len(tc.statement))
		}
	}

	accountID := "11111111-1111-4111-8111-111111111111"
	statement := []byte("statement")
	digest, err := keyTransparencyEventDigest(accountID, statement)
	if err != nil {
		t.Fatal(err)
	}
	key := config.KeyTransparencyKnownEventPrefix + accountID + ":" + hex.EncodeToString(digest[:])
	if err := store.Set(config.Service, key, "malformed"); err != nil {
		t.Fatal(err)
	}
	if _, err := HasKnownKeyTransparencyEvent(store, accountID, statement); err == nil || errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("malformed record should fail closed, got %v", err)
	}
}

func TestKnownKeyTransparencyEvent_IsOnlyKnownAfterPendingAcceptance(t *testing.T) {
	store := NewMemorySecretStore()
	accountID := "11111111-1111-4111-8111-111111111111"
	statement := []byte("signed statement")
	pendingID, err := PendingKeyTransparencyEventID([]byte("new public key"))
	if err != nil {
		t.Fatal(err)
	}
	if err := StageKeyTransparencyEvent(store, accountID, pendingID, statement); err != nil {
		t.Fatalf("stage event: %v", err)
	}
	if known, err := HasKnownKeyTransparencyEvent(store, accountID, statement); err != nil || known {
		t.Fatalf("pending event became known before server acceptance: known=%t err=%v", known, err)
	}
	if err := PromoteKeyTransparencyEvent(store, pendingID); err != nil {
		t.Fatalf("promote event: %v", err)
	}
	if known, err := HasKnownKeyTransparencyEvent(store, accountID, statement); err != nil || !known {
		t.Fatalf("accepted event was not known: known=%t err=%v", known, err)
	}
	if _, err := store.Get(config.Service, config.KeyTransparencyPendingEventPrefix+pendingID); !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("pending event survived promotion: %v", err)
	}
}

func TestKnownKeyTransparencyEvent_AbortRemovesPendingOnly(t *testing.T) {
	store := NewMemorySecretStore()
	accountID := "11111111-1111-4111-8111-111111111111"
	statement := []byte("signed statement")
	pendingID, err := PendingKeyTransparencyEventID([]byte("new public key"))
	if err != nil {
		t.Fatal(err)
	}
	if err := StageKeyTransparencyEvent(store, accountID, pendingID, statement); err != nil {
		t.Fatal(err)
	}
	if err := DeletePendingKeyTransparencyEvent(store, pendingID); err != nil {
		t.Fatal(err)
	}
	if known, err := HasKnownKeyTransparencyEvent(store, accountID, statement); err != nil || known {
		t.Fatalf("aborted event became known: known=%t err=%v", known, err)
	}
}
