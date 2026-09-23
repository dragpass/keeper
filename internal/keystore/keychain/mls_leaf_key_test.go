package keychain

import (
	"crypto/ed25519"
	"encoding/json"
	"testing"

	"github.com/dragpass/keeper/config"
)

func TestMLSLeafKey_RoundTripAndRefusesAMismatchedPair(t *testing.T) {
	store := NewMemorySecretStore()
	if _, found, err := GetMLSLeafKey(store); found || err != nil {
		t.Fatalf("empty store: found=%v err=%v", found, err)
	}

	public, secret, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	key := MLSLeafKey{AccountID: "a", DeviceID: "d", SecretKey: secret, PublicKey: public, Declaration: []byte("decl")}
	if err := SaveMLSLeafKey(store, key); err != nil {
		t.Fatal(err)
	}
	got, found, err := GetMLSLeafKey(store)
	if err != nil || !found || string(got.PublicKey) != string(public) || string(got.SecretKey) != string(secret) ||
		string(got.Declaration) != "decl" {
		t.Fatalf("round trip: found=%v err=%v", found, err)
	}

	otherPublic, _, _ := ed25519.GenerateKey(nil)
	if err := SaveMLSLeafKey(store, MLSLeafKey{AccountID: "a", DeviceID: "d", SecretKey: secret, PublicKey: otherPublic, Declaration: []byte("decl")}); err == nil {
		t.Fatal("saved a public key that is not the secret key's")
	}
	if err := SaveMLSLeafKey(store, MLSLeafKey{AccountID: "a", SecretKey: secret, PublicKey: public, Declaration: []byte("decl")}); err == nil {
		t.Fatal("saved a record with no device")
	}

	if removed, err := DeleteMLSLeafKey(store); !removed || err != nil {
		t.Fatalf("delete: removed=%v err=%v", removed, err)
	}
	if removed, err := DeleteMLSLeafKey(store); removed || err != nil {
		t.Fatalf("second delete: removed=%v err=%v", removed, err)
	}
}

func TestMLSLeafKey_RefusesAKeyWithoutADeclaration(t *testing.T) {
	store := NewMemorySecretStore()
	public, secret, _ := ed25519.GenerateKey(nil)
	if err := SaveMLSLeafKey(store, MLSLeafKey{AccountID: "a", DeviceID: "d", SecretKey: secret, PublicKey: public}); err == nil {
		t.Fatal("saved a key with no declaration")
	}
	tooBig := make([]byte, MLSLeafDeclarationMaxBytes+1)
	if err := SaveMLSLeafKey(store, MLSLeafKey{AccountID: "a", DeviceID: "d", SecretKey: secret, PublicKey: public, Declaration: tooBig}); err == nil {
		t.Fatal("saved an oversized declaration")
	}
}

// A 0.0.43 record still reads, with no declaration, so the device can enroll
// again rather than being told its key is unreadable.
func TestMLSLeafKey_ReadsAVersionOneRecordWithoutADeclaration(t *testing.T) {
	store := NewMemorySecretStore()
	public, secret, _ := ed25519.GenerateKey(nil)
	raw, _ := json.Marshal(map[string]any{
		"v": 1, "account_id": "a", "device_id": "d", "secret_key": secret, "public_key": public,
	})
	if err := store.Set(config.Service, config.MLSLeafSignatureKey, string(raw)); err != nil {
		t.Fatal(err)
	}
	got, found, err := GetMLSLeafKey(store)
	if err != nil || !found || got.Declaration != nil {
		t.Fatalf("v1 record: found=%v err=%v declaration=%v", found, err, got.Declaration != nil)
	}
}

func TestMLSLeafKey_DecodesStrictly(t *testing.T) {
	store := NewMemorySecretStore()
	public, secret, _ := ed25519.GenerateKey(nil)
	for name, extra := range map[string]map[string]any{
		"unknown field":         {"v": 2, "declaration": []byte("d"), "pending": true},
		"v1 with a declaration": {"v": 1, "declaration": []byte("d")},
	} {
		fields := map[string]any{"account_id": "a", "device_id": "d", "secret_key": secret, "public_key": public}
		for k, v := range extra {
			fields[k] = v
		}
		raw, _ := json.Marshal(fields)
		_ = store.Set(config.Service, config.MLSLeafSignatureKey, string(raw))
		if _, _, err := GetMLSLeafKey(store); err == nil {
			t.Errorf("%s: record was accepted", name)
		}
	}
	good, _ := json.Marshal(map[string]any{
		"v": 2, "account_id": "a", "device_id": "d", "secret_key": secret, "public_key": public, "declaration": []byte("d"),
	})
	_ = store.Set(config.Service, config.MLSLeafSignatureKey, string(good)+" {}")
	if _, _, err := GetMLSLeafKey(store); err == nil {
		t.Error("trailing content was accepted")
	}
}
