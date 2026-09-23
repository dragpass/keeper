// key_package_pool.go — the private keys of this device's outstanding
// KeyPackages, one sealed file per owner.
//
// A KeyPackage is uploaded now and consumed whenever somebody adds this device
// to a group, which may be in another process days later. Its two private keys
// (the HPKE init key and the leaf encryption key) have to survive until then,
// or the Welcome addressed to it can never be opened. They live here rather
// than in the keyring because there can be as many as the pool holds, which is
// more than a keyring entry fits, and because this directory is already what
// guards the group state the same keys lead to.
//
//	<owner dir>/key-packages.pool   magic "DPKP" | version | IV | AES-GCM(body)
//
// The body is {"v":1,"entries":[{"ref","not_after","private"}]}. ref is the
// KeyPackage reference a Welcome names, not_after the KeyPackage's own end,
// and private the opaque entry the MLS library produced. The file is sealed
// under a subkey of the owner's seal key, so purging the owner (which deletes
// the seal key) makes a leftover copy unopenable, and it is replaced whole
// through replaceFile like every record here.
//
// Nothing about an entry's private part reaches a log or an error, not even its
// length.
//
// A rewound copy of this file brings back entries for KeyPackages that were
// consumed since. That is harmless: the server marks a KeyPackage consumed when
// it hands it out and never hands it out again, so no Welcome will name one.
// There is no anchor for it for that reason.

package chatstate

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/dragpass/keeper/internal/keystore/secure"
)

const (
	// MaxKeyPackagePoolEntries bounds the file. ariadne serves at most 50
	// unconsumed KeyPackages per device and one generate call makes at most
	// 32, so a pool that is doing its job holds well under this; what pushes
	// it higher is KeyPackages generated and never uploaded. When a write
	// would go over, the entries that expire soonest are dropped. A starting
	// value, not a measured one.
	MaxKeyPackagePoolEntries = 128

	// MaxKeyPackageEntryBytes bounds one private entry: a KeyPackage of at
	// most 8192 bytes plus two keys and framing.
	MaxKeyPackageEntryBytes = 8192 + 1024

	keyPackagePoolFile     = "key-packages.pool"
	keyPackagePoolLock     = "key-packages" + lockSuffix
	keyPackagePoolVersion  = 1
	keyPackagePoolAADLabel = "dragpass.chat.keypackage.pool|1|"
	keyPackageRefMaxBytes  = 64
)

var (
	keyPackagePoolMagic = [4]byte{'D', 'P', 'K', 'P'}

	errKeyPackagePoolMalformed = errors.New("key package pool is malformed")

	// ErrKeyPackageNotInPool — no unexpired private entry for any reference a
	// Welcome names. This device cannot join from it.
	ErrKeyPackageNotInPool = errors.New("no key package private keys for this welcome")
)

// KeyPackagePoolEntry is one KeyPackage's private entry. Private is secret and
// the caller's to wipe.
type KeyPackagePoolEntry struct {
	Ref      []byte `json:"ref"`
	NotAfter uint64 `json:"not_after"`
	Private  []byte `json:"private"`
}

type keyPackagePool struct {
	V       int                   `json:"v"`
	Entries []KeyPackagePoolEntry `json:"entries"`
}

func (p *keyPackagePool) wipe() {
	for i := range p.Entries {
		secure.Zeroize(p.Entries[i].Private)
	}
}

// AddKeyPackages stores the private entries of freshly generated KeyPackages.
// It must return before the KeyPackages are handed to anyone, because a
// KeyPackage whose keys were not kept is one nobody can ever be added
// through. Expired entries are dropped on the same write.
func (s *Store) AddKeyPackages(entries []KeyPackagePoolEntry, now time.Time) error {
	for _, e := range entries {
		if len(e.Ref) == 0 || len(e.Ref) > keyPackageRefMaxBytes ||
			len(e.Private) == 0 || len(e.Private) > MaxKeyPackageEntryBytes || e.NotAfter == 0 {
			return errors.New("key package pool entry is unusable")
		}
	}
	return s.withKeyPackagePool(func(pool *keyPackagePool) (bool, error) {
		pool.prune(now)
		for _, e := range entries {
			pool.remove(e.Ref)
			pool.Entries = append(pool.Entries, KeyPackagePoolEntry{
				Ref: bytes.Clone(e.Ref), NotAfter: e.NotAfter, Private: bytes.Clone(e.Private),
			})
		}
		pool.bound()
		return true, nil
	})
}

// LookupKeyPackage returns a copy of the first unexpired entry among refs, the
// references a Welcome is addressed to. It writes nothing: the entry is
// deleted only after the group state it led to is on disk
// (DeleteKeyPackage), so a crash in between leaves the invitation joinable.
func (s *Store) LookupKeyPackage(refs [][]byte, now time.Time) (KeyPackagePoolEntry, error) {
	var found KeyPackagePoolEntry
	err := s.withKeyPackagePool(func(pool *keyPackagePool) (bool, error) {
		for _, ref := range refs {
			for _, e := range pool.Entries {
				if bytes.Equal(e.Ref, ref) && !e.expired(now) {
					found = KeyPackagePoolEntry{
						Ref: bytes.Clone(e.Ref), NotAfter: e.NotAfter, Private: bytes.Clone(e.Private),
					}
					return false, nil
				}
			}
		}
		return false, ErrKeyPackageNotInPool
	})
	return found, err
}

// DeleteKeyPackage removes one entry, once the join it served is persisted.
// Idempotent. Expired entries go on the same write.
func (s *Store) DeleteKeyPackage(ref []byte, now time.Time) error {
	return s.withKeyPackagePool(func(pool *keyPackagePool) (bool, error) {
		before := len(pool.Entries)
		pool.prune(now)
		pool.remove(ref)
		return len(pool.Entries) != before, nil
	})
}

// KeyPackagePoolSize reports how many unexpired entries the pool holds. It is
// for tests and diagnostics; the count is not secret, the entries are.
func (s *Store) KeyPackagePoolSize(now time.Time) (int, error) {
	n := 0
	err := s.withKeyPackagePool(func(pool *keyPackagePool) (bool, error) {
		for _, e := range pool.Entries {
			if !e.expired(now) {
				n++
			}
		}
		return false, nil
	})
	return n, err
}

func (e KeyPackagePoolEntry) expired(now time.Time) bool {
	return uint64(now.Unix()) >= e.NotAfter
}

func (p *keyPackagePool) prune(now time.Time) {
	kept := p.Entries[:0]
	for _, e := range p.Entries {
		if e.expired(now) {
			secure.Zeroize(e.Private)
			continue
		}
		kept = append(kept, e)
	}
	p.Entries = kept
}

func (p *keyPackagePool) remove(ref []byte) {
	kept := p.Entries[:0]
	for _, e := range p.Entries {
		if bytes.Equal(e.Ref, ref) {
			secure.Zeroize(e.Private)
			continue
		}
		kept = append(kept, e)
	}
	p.Entries = kept
}

// bound drops the entries that expire soonest until the pool fits. Dropping
// one whose KeyPackage is still on the server makes that invitation
// unjoinable; refusing the write instead would stop this device from making
// KeyPackages at all until enough of the pool expired, which is the worse
// failure for a device nobody can add.
func (p *keyPackagePool) bound() {
	if len(p.Entries) <= MaxKeyPackagePoolEntries {
		return
	}
	sort.SliceStable(p.Entries, func(i, j int) bool { return p.Entries[i].NotAfter < p.Entries[j].NotAfter })
	drop := len(p.Entries) - MaxKeyPackagePoolEntries
	for i := range drop {
		secure.Zeroize(p.Entries[i].Private)
	}
	p.Entries = p.Entries[drop:]
}

// withKeyPackagePool is the locked read / modify / replace cycle. fn reports
// whether it changed the pool; only then is the file rewritten.
func (s *Store) withKeyPackagePool(fn func(*keyPackagePool) (bool, error)) error {
	dir := s.ownerDir()
	if err := ensureOwnerOnlyDir(s.root, dir); err != nil {
		return err
	}
	release, err := acquireConversationLock(filepath.Join(dir, keyPackagePoolLock), s.lockTimeout)
	if err != nil {
		return err
	}
	defer release()

	path := filepath.Join(dir, keyPackagePoolFile)
	pool, err := s.readKeyPackagePool(dir, path)
	if err != nil {
		return err
	}
	defer pool.wipe()
	changed, err := fn(pool)
	if err != nil || !changed {
		return err
	}
	return s.writeKeyPackagePool(dir, path, pool)
}

func (s *Store) keyPackagePoolAAD() []byte {
	return []byte(keyPackagePoolAADLabel + s.owner)
}

func (s *Store) readKeyPackagePool(dir, path string) (*keyPackagePool, error) {
	s.sweepTempFiles(dir)
	sealed, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return &keyPackagePool{V: keyPackagePoolVersion}, nil
		}
		return nil, err
	}
	const header = 4 + 1 + ivBytes
	if len(sealed) < header || [4]byte(sealed[0:4]) != keyPackagePoolMagic || sealed[4] != keyPackagePoolVersion {
		return nil, errKeyPackagePoolMalformed
	}
	gcm, err := newGCM(s.poolKey)
	if err != nil {
		return nil, err
	}
	body, err := gcm.Open(nil, sealed[5:header], sealed[header:], s.keyPackagePoolAAD())
	if err != nil {
		return nil, errKeyPackagePoolMalformed
	}
	defer secure.Zeroize(body)
	var pool keyPackagePool
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&pool); err != nil || dec.More() || pool.V != keyPackagePoolVersion {
		pool.wipe()
		return nil, errKeyPackagePoolMalformed
	}
	return &pool, nil
}

func (s *Store) writeKeyPackagePool(dir, path string, pool *keyPackagePool) error {
	if len(pool.Entries) == 0 {
		if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		return syncDir(dir)
	}
	pool.V = keyPackagePoolVersion
	body, err := json.Marshal(pool)
	if err != nil {
		return err
	}
	defer secure.Zeroize(body)
	gcm, err := newGCM(s.poolKey)
	if err != nil {
		return err
	}
	const header = 4 + 1 + ivBytes
	out := make([]byte, header, header+len(body)+gcm.Overhead())
	copy(out[0:4], keyPackagePoolMagic[:])
	out[4] = keyPackagePoolVersion
	iv := out[5:header]
	if _, err := rand.Read(iv); err != nil {
		return err
	}
	return replaceFile(dir, path, gcm.Seal(out, iv, body, s.keyPackagePoolAAD()))
}
