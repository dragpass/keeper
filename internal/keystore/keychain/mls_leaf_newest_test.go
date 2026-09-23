package keychain

import (
	"testing"

	"github.com/dragpass/keeper/config"
)

const (
	newestOwner = "a0000000-0000-4000-8000-000000000001"
	newestPeer  = "b0000000-0000-4000-8000-000000000002"
)

func TestMLSLeafNewest_SaveWritesVersion2AndReadsItBack(t *testing.T) {
	store := NewMemorySecretStore()
	want := MLSLeafNewest{NotBefore: 1758000000, Fingerprint: "ab", FirstSeenAt: 1758003600}
	if err := SaveMLSLeafNewest(store, newestOwner, newestPeer, want); err != nil {
		t.Fatal(err)
	}
	got, found, err := GetMLSLeafNewest(store, newestOwner, newestPeer)
	want.V = MLSLeafNewestVersion
	if err != nil || !found || got != want {
		t.Fatalf("got %+v, %v, %v; want %+v", got, found, err, want)
	}
	if err := SaveMLSLeafNewest(store, newestOwner, newestPeer, MLSLeafNewest{NotBefore: 1, Fingerprint: "ab"}); err == nil {
		t.Fatal("a record without first_seen_at was saved")
	}
}

func TestMLSLeafNewest_AVersion1RecordReadsWithoutFirstSeenAt(t *testing.T) {
	store := NewMemorySecretStore()
	if err := store.Set(config.Service, MLSLeafNewestAccount(newestOwner, newestPeer),
		`{"v":1,"not_before":1758000000,"fingerprint":"ab"}`); err != nil {
		t.Fatal(err)
	}
	got, found, err := GetMLSLeafNewest(store, newestOwner, newestPeer)
	if err != nil || !found || got.FirstSeenAt != 0 || got.NotBefore != 1758000000 {
		t.Fatalf("got %+v, %v, %v", got, found, err)
	}
}

func TestMLSLeafNewest_MalformedRecordsAreRefused(t *testing.T) {
	for name, raw := range map[string]string{
		"v1 with first_seen_at":    `{"v":1,"not_before":1758000000,"fingerprint":"ab","first_seen_at":1758003600}`,
		"v2 without first_seen_at": `{"v":2,"not_before":1758000000,"fingerprint":"ab"}`,
		"v2 zero first_seen_at":    `{"v":2,"not_before":1758000000,"fingerprint":"ab","first_seen_at":0}`,
		"v2 negative":              `{"v":2,"not_before":1758000000,"fingerprint":"ab","first_seen_at":-1}`,
		"unknown version":          `{"v":3,"not_before":1758000000,"fingerprint":"ab","first_seen_at":1}`,
		"unknown field":            `{"v":2,"not_before":1758000000,"fingerprint":"ab","first_seen_at":1,"x":1}`,
		"string first_seen_at":     `{"v":2,"not_before":1758000000,"fingerprint":"ab","first_seen_at":"1"}`,
		"trailing value":           `{"v":2,"not_before":1758000000,"fingerprint":"ab","first_seen_at":1} {}`,
	} {
		store := NewMemorySecretStore()
		if err := store.Set(config.Service, MLSLeafNewestAccount(newestOwner, newestPeer), raw); err != nil {
			t.Fatal(err)
		}
		if _, _, err := GetMLSLeafNewest(store, newestOwner, newestPeer); err == nil {
			t.Errorf("%s: read without error", name)
		}
	}
}
