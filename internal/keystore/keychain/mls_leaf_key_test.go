package keychain

import (
	"crypto/ed25519"
	"testing"
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
	key := MLSLeafKey{AccountID: "a", DeviceID: "d", SecretKey: secret, PublicKey: public}
	if err := SaveMLSLeafKey(store, key); err != nil {
		t.Fatal(err)
	}
	got, found, err := GetMLSLeafKey(store)
	if err != nil || !found || string(got.PublicKey) != string(public) || string(got.SecretKey) != string(secret) {
		t.Fatalf("round trip: found=%v err=%v", found, err)
	}

	otherPublic, _, _ := ed25519.GenerateKey(nil)
	if err := SaveMLSLeafKey(store, MLSLeafKey{AccountID: "a", DeviceID: "d", SecretKey: secret, PublicKey: otherPublic}); err == nil {
		t.Fatal("saved a public key that is not the secret key's")
	}
	if err := SaveMLSLeafKey(store, MLSLeafKey{AccountID: "a", SecretKey: secret, PublicKey: public}); err == nil {
		t.Fatal("saved a record with no device")
	}

	if removed, err := DeleteMLSLeafKey(store); !removed || err != nil {
		t.Fatalf("delete: removed=%v err=%v", removed, err)
	}
	if removed, err := DeleteMLSLeafKey(store); removed || err != nil {
		t.Fatalf("second delete: removed=%v err=%v", removed, err)
	}
}
