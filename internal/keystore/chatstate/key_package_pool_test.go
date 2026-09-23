package chatstate

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

var poolNow = time.Unix(1_790_000_000, 0)

func poolEntry(tag byte, notAfter time.Time) KeyPackagePoolEntry {
	return KeyPackagePoolEntry{
		Ref:      bytes.Repeat([]byte{tag}, 32),
		NotAfter: uint64(notAfter.Unix()),
		Private:  bytes.Repeat([]byte{tag ^ 0x5a}, 200),
	}
}

func poolPath(s *Store) string { return filepath.Join(s.ownerDir(), keyPackagePoolFile) }

func TestKeyPackagePool_AnEntryIsFoundByAnyReferenceTheWelcomeNames(t *testing.T) {
	store, _ := newTestStore(t)
	a, b := poolEntry(1, poolNow.Add(time.Hour)), poolEntry(2, poolNow.Add(time.Hour))
	if err := store.AddKeyPackages([]KeyPackagePoolEntry{a, b}, poolNow); err != nil {
		t.Fatal(err)
	}

	got, err := store.LookupKeyPackage([][]byte{bytes.Repeat([]byte{9}, 32), b.Ref}, poolNow)
	if err != nil || !bytes.Equal(got.Private, b.Private) || got.NotAfter != b.NotAfter {
		t.Fatalf("lookup = %v", err)
	}
	if _, err := store.LookupKeyPackage([][]byte{bytes.Repeat([]byte{9}, 32)}, poolNow); !errors.Is(err, ErrKeyPackageNotInPool) {
		t.Fatalf("lookup of an unknown reference = %v", err)
	}

	// Lookup writes nothing; the entry stays until the join is persisted.
	if n, _ := store.KeyPackagePoolSize(poolNow); n != 2 {
		t.Fatalf("pool size after lookup = %d", n)
	}
	if err := store.DeleteKeyPackage(b.Ref, poolNow); err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteKeyPackage(b.Ref, poolNow); err != nil {
		t.Fatalf("a second delete: %v", err)
	}
	if _, err := store.LookupKeyPackage([][]byte{b.Ref}, poolNow); !errors.Is(err, ErrKeyPackageNotInPool) {
		t.Fatal("a deleted entry was still found")
	}
}

func TestKeyPackagePool_SurvivesAFreshStoreAndIsSealed(t *testing.T) {
	store, secrets := newTestStore(t)
	e := poolEntry(3, poolNow.Add(time.Hour))
	if err := store.AddKeyPackages([]KeyPackagePoolEntry{e}, poolNow); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(poolPath(store))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, e.Private) || bytes.Contains(raw, e.Ref) {
		t.Fatal("the pool file exposes an entry")
	}

	again, err := Open(secrets, testOwner)
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	if got, err := again.LookupKeyPackage([][]byte{e.Ref}, poolNow); err != nil || !bytes.Equal(got.Private, e.Private) {
		t.Fatalf("a later process could not find the entry: %v", err)
	}

	other, err := Open(secrets, "99999999-9999-4999-8999-999999999999")
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if err := os.MkdirAll(other.ownerDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(poolPath(other), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := other.LookupKeyPackage([][]byte{e.Ref}, poolNow); err == nil || errors.Is(err, ErrKeyPackageNotInPool) {
		t.Fatalf("another owner's pool opened: %v", err)
	}

	raw[len(raw)-1] ^= 1
	if err := os.WriteFile(poolPath(store), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LookupKeyPackage([][]byte{e.Ref}, poolNow); err == nil || errors.Is(err, ErrKeyPackageNotInPool) {
		t.Fatalf("a tampered pool opened: %v", err)
	}
}

// Expired entries are deleted on every write, and an expired entry is never
// handed out even before a write has removed it.
func TestKeyPackagePool_ExpiredEntriesAreNeverServedAndGoOnEveryWrite(t *testing.T) {
	store, _ := newTestStore(t)
	soon, later := poolEntry(4, poolNow.Add(time.Minute)), poolEntry(5, poolNow.Add(time.Hour))
	if err := store.AddKeyPackages([]KeyPackagePoolEntry{soon, later}, poolNow); err != nil {
		t.Fatal(err)
	}
	after := poolNow.Add(2 * time.Minute)
	if _, err := store.LookupKeyPackage([][]byte{soon.Ref}, after); !errors.Is(err, ErrKeyPackageNotInPool) {
		t.Fatal("an expired entry was served")
	}
	if _, err := store.LookupKeyPackage([][]byte{soon.Ref}, soon.expiresAt()); !errors.Is(err, ErrKeyPackageNotInPool) {
		t.Fatal("an entry was served at its not_after")
	}

	if err := store.DeleteKeyPackage(bytes.Repeat([]byte{9}, 32), after); err != nil {
		t.Fatal(err)
	}
	if n, _ := store.KeyPackagePoolSize(poolNow); n != 1 {
		t.Fatalf("a write kept an expired entry: %d left", n)
	}

	fresh := poolEntry(6, after.Add(time.Hour))
	if err := store.AddKeyPackages([]KeyPackagePoolEntry{fresh}, later.expiresAt()); err != nil {
		t.Fatal(err)
	}
	if n, _ := store.KeyPackagePoolSize(poolNow); n != 1 {
		t.Fatalf("an add kept an expired entry: %d entries", n)
	}
}

func TestKeyPackagePool_IsBoundedByDroppingWhatExpiresSoonest(t *testing.T) {
	store, _ := newTestStore(t)
	var batch []KeyPackagePoolEntry
	for i := range MaxKeyPackagePoolEntries + 3 {
		e := poolEntry(byte(i), poolNow.Add(time.Duration(i+1)*time.Minute))
		e.Ref = append(bytes.Repeat([]byte{0xee}, 30), byte(i>>8), byte(i))
		batch = append(batch, e)
	}
	if err := store.AddKeyPackages(batch, poolNow); err != nil {
		t.Fatal(err)
	}
	if n, _ := store.KeyPackagePoolSize(poolNow); n != MaxKeyPackagePoolEntries {
		t.Fatalf("pool holds %d, want %d", n, MaxKeyPackagePoolEntries)
	}
	for i, e := range batch {
		_, err := store.LookupKeyPackage([][]byte{e.Ref}, poolNow)
		if dropped := i < 3; dropped != errors.Is(err, ErrKeyPackageNotInPool) {
			t.Fatalf("entry %d: dropped=%v err=%v", i, dropped, err)
		}
	}
}

func TestKeyPackagePool_RefusesAnUnusableEntryAndWritesNothing(t *testing.T) {
	store, _ := newTestStore(t)
	good := poolEntry(7, poolNow.Add(time.Hour))
	for name, bad := range map[string]KeyPackagePoolEntry{
		"no ref":       {NotAfter: good.NotAfter, Private: good.Private},
		"no private":   {Ref: good.Ref, NotAfter: good.NotAfter},
		"no not_after": {Ref: good.Ref, Private: good.Private},
		"huge private": {Ref: good.Ref, NotAfter: good.NotAfter, Private: make([]byte, MaxKeyPackageEntryBytes+1)},
		"long ref":     {Ref: make([]byte, keyPackageRefMaxBytes+1), NotAfter: good.NotAfter, Private: good.Private},
	} {
		if err := store.AddKeyPackages([]KeyPackagePoolEntry{good, bad}, poolNow); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := os.Stat(poolPath(store)); !os.IsNotExist(err) {
		t.Fatal("a refused add wrote the pool")
	}
}

// Logout (chat_state_purge) and reset both go through purgeOwner, which
// removes the directory the pool lives in and then the seal key it is sealed
// under.
func TestKeyPackagePool_PurgeRemovesThePoolAndItsKey(t *testing.T) {
	store, secrets := newTestStore(t)
	e := poolEntry(8, poolNow.Add(time.Hour))
	if err := store.AddKeyPackages([]KeyPackagePoolEntry{e}, poolNow); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(poolPath(store))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Purge(secrets, testOwner); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(poolPath(store)); !os.IsNotExist(err) {
		t.Fatal("the pool survived the purge")
	}

	// A copy restored afterwards does not open under the new seal key.
	fresh, err := Open(secrets, testOwner)
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	if err := os.WriteFile(poolPath(fresh), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := fresh.LookupKeyPackage([][]byte{e.Ref}, poolNow); err == nil || errors.Is(err, ErrKeyPackageNotInPool) {
		t.Fatalf("a pool restored after the purge opened: %v", err)
	}
}

func (e KeyPackagePoolEntry) expiresAt() time.Time { return time.Unix(int64(e.NotAfter), 0) }
