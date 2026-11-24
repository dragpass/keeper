package keychain

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"testing"

	"github.com/dragpass/keeper/config"
)

func TestArchiveSessionIndexExceedsOnePlatformItem(t *testing.T) {
	store := NewMemorySecretStore()
	var ids []string
	for i := 0; i < 170; i++ {
		id := fmt.Sprintf("00000000-0000-4000-8000-%012d", i)
		if err := AddArchiveSessionOrg(store, id); err != nil {
			t.Fatalf("add organization %d: %v", i+1, err)
		}
		ids = append(ids, id)
	}
	got, err := ListArchiveSessionOrgs(store)
	if err != nil || !slices.Equal(got, ids) {
		t.Fatalf("listed %d of %d organizations: %v", len(got), len(ids), err)
	}
	for _, id := range ids[:150] {
		if err := RemoveArchiveSessionOrg(store, id); err != nil {
			t.Fatal(err)
		}
	}
	got, err = ListArchiveSessionOrgs(store)
	if err != nil || !slices.Equal(got, ids[150:]) {
		t.Fatalf("listed %d remaining organizations: %v", len(got), err)
	}
}

func TestArchiveSessionIndexReadsOverflowAfterLegacyRootRemoval(t *testing.T) {
	store := NewMemorySecretStore()
	for i := range 70 {
		if err := AddArchiveSessionOrg(store, fmt.Sprintf("00000000-0000-4000-8000-%012d", i)); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Delete(config.Service, config.OrgArchiveSessionIndex); err != nil {
		t.Fatal(err)
	}
	got, err := ListArchiveSessionOrgs(store)
	if err != nil || len(got) != 5 {
		t.Fatalf("listed %d overflow entries after root deletion: %v", len(got), err)
	}
	// Simulate an old writer indexing a slot it cannot see in overflow.
	legacy, err := encodeArchiveSessionPage(got[:1])
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Set(config.Service, config.OrgArchiveSessionIndex, string(legacy)); err != nil {
		t.Fatal(err)
	}
	orgs, err := ListArchiveSessionOrgs(store)
	if err != nil || !slices.Equal(orgs, got) {
		t.Fatalf("duplicate legacy entry changed the listing: %v, %v", orgs, err)
	}
	if err := RemoveArchiveSessionOrg(store, got[0]); err != nil {
		t.Fatal(err)
	}
	orgs, err = ListArchiveSessionOrgs(store)
	if err != nil || !slices.Equal(orgs, got[1:]) {
		t.Fatalf("removing duplicate entry changed other slots: %v, %v", orgs, err)
	}
}

func TestEmptyArchiveSessionOverflowPageIsUnreadable(t *testing.T) {
	store := NewMemorySecretStore()
	if err := AddArchiveSessionOrg(store, "org0"); err != nil {
		t.Fatal(err)
	}
	if err := store.Set(config.Service, archiveSessionIndexKey(1), ""); err != nil {
		t.Fatal(err)
	}
	if err := store.Set(config.Service, archiveSessionIndexKey(2), `{"v":1,"orgs":["org2"]}`); err != nil {
		t.Fatal(err)
	}
	before := store.Snapshot()
	if _, err := ListArchiveSessionOrgs(store); !errors.Is(err, ErrArchiveSessionIndexUnreadable) {
		t.Fatalf("listing returned %v on a damaged overflow page", err)
	}
	if err := AddArchiveSessionOrg(store, "new"); !errors.Is(err, ErrArchiveSessionIndexUnreadable) {
		t.Fatalf("add returned %v on a damaged overflow page", err)
	}
	if !maps.Equal(before, store.Snapshot()) {
		t.Fatal("add changed a damaged index")
	}
}

func TestArchiveSessionIndexSupplementOverflowWriteCanBeRetried(t *testing.T) {
	store := NewMemorySecretStore()
	blocked := &failSetOnceStore{SecretStore: store, account: archiveSessionIndexKey(1)}
	var expected []string
	for i := range 40 {
		org := fmt.Sprintf("00000000-0000-4000-8000-%012d", i)
		for _, slot := range []string{org, org + ":supplement"} {
			if err := AddArchiveSessionOrg(blocked, slot); err != nil {
				if !blocked.failed {
					t.Fatal(err)
				}
				got, err := ListArchiveSessionOrgs(store)
				if err != nil || !slices.Equal(got, expected) {
					t.Fatalf("failed write changed the previous entries: %v", err)
				}
				if err := AddArchiveSessionOrg(blocked, slot); err != nil {
					t.Fatal(err)
				}
			}
			expected = append(expected, slot)
		}
	}
	if !blocked.failed {
		t.Fatal("no overflow write exercised")
	}
	got, err := ListArchiveSessionOrgs(store)
	slices.Sort(got)
	slices.Sort(expected)
	if err != nil || !slices.Equal(got, expected) {
		t.Fatalf("unexpected entries after retry: %v", err)
	}
}
