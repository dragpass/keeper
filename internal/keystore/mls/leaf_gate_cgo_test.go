//go:build mls && cgo

package mls

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/dragpass/keeper/config"
	"github.com/dragpass/keeper/internal/keystore/keychain"
)

// threeMemberAttempt is alice and bob in a group, and a Commit alice built
// adding carol, which bob has not processed yet.
func threeMemberAttempt(t testing.TB) (bob *Session, commit []byte, carolKP []byte) {
	t.Helper()
	alice, bob, _ := twoMemberGroup(t)
	carol := newSession(t, "carol@device-1")
	carolKP, err := carol.KeyPackage()
	if err != nil {
		t.Fatal(err)
	}
	commit, _, _, err = alice.CommitAddMemberVerified(carolKP, trustAll{})
	if err != nil {
		t.Fatalf("commit add carol: %v", err)
	}
	return bob, commit, carolKP
}

// The collect pass is only what the verifier is asked about. What decides is
// the enforce pass, and it admits exactly what was approved: a narrower list
// than the collect pass saw is refused, with nothing applied.
func TestTheEnforcePassRefusesALeafTheCollectPassSawButGoDidNotApprove(t *testing.T) {
	bob, commit, carolKP := threeMemberAttempt(t)
	dave := newSession(t, "dave@device-1")
	daveKP, err := dave.KeyPackage()
	if err != nil {
		t.Fatal(err)
	}
	daveLeaf, err := keyPackageLeaf(daveKP)
	if err != nil {
		t.Fatal(err)
	}
	carolLeaf, err := keyPackageLeaf(carolKP)
	if err != nil {
		t.Fatal(err)
	}
	altered := carolLeaf
	altered.Declaration = []byte("a declaration go never saw")

	seen, _, err := bob.processCollect(commit)
	if err != nil || len(seen) != 1 || !bytes.Equal(seen[0].Identity, carolLeaf.Identity) {
		t.Fatalf("collect = %d leaves, %v; want carol", len(seen), err)
	}

	blob, err := bob.Flush()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name     string
		approval []Leaf
		// The gate refuses a credential and key nobody approved inside
		// mls-rs, before the group moves. Declaration bytes the gate cannot
		// see are compared after, and that refusal drops the session's group
		// so nothing can build on it; the record never saw either.
		dropsGroup bool
	}{
		{"nothing approved", nil, false},
		{"somebody else approved", []Leaf{daveLeaf}, false},
		{"other declaration approved", []Leaf{altered}, true},
	} {
		if err := bob.Load(blob); err != nil {
			t.Fatal(err)
		}
		if err := bob.approve(tc.approval); err != nil {
			t.Fatal(err)
		}
		if _, err := bob.Process(commit); !errors.Is(err, ErrLeafUntrusted) {
			t.Errorf("%s: process = %v; want ErrLeafUntrusted", tc.name, err)
		}
		epoch, err := bob.Epoch()
		switch {
		case tc.dropsGroup && err == nil:
			t.Errorf("%s: the session kept a group after a post-check refusal", tc.name)
		case !tc.dropsGroup && (err != nil || epoch != 1):
			t.Errorf("%s: epoch = %d, %v; want the untouched 1", tc.name, epoch, err)
		}
	}

	// The same Commit with carol's real leaf approved goes through.
	if err := bob.Load(blob); err != nil {
		t.Fatal(err)
	}
	if err := bob.approve([]Leaf{carolLeaf}); err != nil {
		t.Fatal(err)
	}
	if got, err := bob.Process(commit); err != nil || got.Epoch != 2 {
		t.Fatalf("approved process = %d, %v", got.Epoch, err)
	}
}

func TestANilVerifierIsARefusalNotAPass(t *testing.T) {
	bob, commit, _ := threeMemberAttempt(t)
	if _, err := bob.ProcessVerified(commit, nil); !errors.Is(err, ErrLeafUntrusted) {
		t.Fatalf("process with no verifier = %v; want ErrLeafUntrusted", err)
	}
	if epoch, err := bob.Epoch(); err != nil || epoch != 1 {
		t.Fatalf("epoch = %d, %v; want the untouched 1", epoch, err)
	}
}

type refuseAll struct{ asked [][]Leaf }

func (r *refuseAll) VerifyLeaves(leaves []Leaf) error {
	r.asked = append(r.asked, leaves)
	return ErrLeafUntrusted
}

func (r *refuseAll) Commit() error { return nil }

func TestARefusingVerifierLeavesTheGroupUntouched(t *testing.T) {
	bob, commit, _ := threeMemberAttempt(t)
	before, err := bob.Flush()
	if err != nil {
		t.Fatal(err)
	}
	v := &refuseAll{}
	if _, err := bob.ProcessVerified(commit, v); !errors.Is(err, ErrLeafUntrusted) {
		t.Fatalf("process = %v", err)
	}
	if len(v.asked) != 1 || len(v.asked[0]) != 1 {
		t.Fatalf("verifier asked %d times", len(v.asked))
	}
	after, err := bob.Flush()
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("the collect pass left a trace in the group state")
	}
}

// An application message adds no leaf and is processed once, with no
// verifier call.
func TestAnApplicationMessageIsNotCollected(t *testing.T) {
	alice, bob, _ := twoMemberGroup(t)
	ct, err := alice.Encrypt([]byte("hi"), nil)
	if err != nil {
		t.Fatal(err)
	}
	v := &refuseAll{}
	got, err := bob.ProcessVerified(ct, v)
	if err != nil || string(got.Plaintext) != "hi" || len(v.asked) != 0 {
		t.Fatalf("process = %v, asked %d", err, len(v.asked))
	}
}

func TestNewDeviceSession_RefusesAKeyWithNoStoredDeclaration(t *testing.T) {
	store := keychain.NewMemorySecretStore()
	// What 0.0.43 wrote: a v1 record with no declaration.
	raw := `{"v":1,"account_id":"a","device_id":"d","secret_key":"` +
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA7aie8zrakLWKjqNAqbw1zZTIVdx3iQ6Y6wEihi1naKQ==" +
		`","public_key":"O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik="}`
	if err := store.Set(config.Service, config.MLSLeafSignatureKey, raw); err != nil {
		t.Fatal(err)
	}
	if _, _, err := NewDeviceSession(store); !errors.Is(err, ErrNoLeafDeclaration) {
		t.Fatalf("NewDeviceSession = %v; want ErrNoLeafDeclaration", err)
	}
}

func TestKeyPackagesAreBoundedAndCarryTheirLifetime(t *testing.T) {
	s := newSession(t, "bob@device-1")
	now := uint64(time.Now().Unix())
	far := now + 10*365*24*60*60
	if _, _, err := s.KeyPackages(0, far); err == nil {
		t.Fatal("zero key packages accepted")
	}
	if _, _, err := s.KeyPackages(MaxKeyPackagesPerCall+1, far); err == nil {
		t.Fatal("too many key packages accepted")
	}
	kps, pool, err := s.KeyPackages(3, far)
	if err != nil || len(kps) != 3 || len(pool) != 3 {
		t.Fatalf("key packages = %d / %d, %v", len(kps), len(pool), err)
	}
	for i, kp := range kps {
		if len(kp.Message) > MaxKeyPackageBytes {
			t.Fatalf("key package of %d bytes", len(kp.Message))
		}
		if kp.NotAfter <= now || kp.NotAfter > now+90*24*60*60 {
			t.Fatalf("not_after %d is not within 90 days of %d", kp.NotAfter, now)
		}
		if len(pool[i].Ref) == 0 || len(pool[i].Private) == 0 || pool[i].NotAfter != kp.NotAfter {
			t.Fatalf("pool entry %d does not describe its key package", i)
		}
		if bytes.Contains(kp.Message, pool[i].Private) {
			t.Fatal("a key package carries its own private entry")
		}
	}
	if bytes.Equal(kps[0].Message, kps[1].Message) || bytes.Equal(pool[0].Ref, pool[1].Ref) {
		t.Fatal("two key packages are the same; each must be single-use")
	}
}

// No KeyPackage outlives the cap, which the caller sets to the declaration's
// not_after; a cap that has passed produces nothing.
func TestKeyPackagesNeverOutliveTheirCap(t *testing.T) {
	s := newSession(t, "bob@device-1")
	now := uint64(time.Now().Unix())
	kps, _, err := s.KeyPackages(2, now+3600)
	if err != nil {
		t.Fatal(err)
	}
	for _, kp := range kps {
		if kp.NotAfter > now+3600 || kp.NotAfter+5 < now+3600 {
			t.Fatalf("not_after %d, want the cap %d", kp.NotAfter, now+3600)
		}
	}
	for _, cap := range []uint64{0, now - 60, now} {
		if _, _, err := s.KeyPackages(1, cap); err == nil {
			t.Fatalf("cap %d produced a key package", cap)
		}
	}
}

// The double-processing cost. A Commit that adds one member, processed once
// (the resting gate with the leaf approved by hand) against processed through
// the collect → verify → enforce path. Each iteration reloads the pre-Commit
// state, which both variants pay equally.
func BenchmarkProcessAddCommit(b *testing.B) {
	bob, commit, carolKP := threeMemberAttempt(b)
	blob, err := bob.Flush()
	if err != nil {
		b.Fatal(err)
	}
	carolLeaf, err := keyPackageLeaf(carolKP)
	if err != nil {
		b.Fatal(err)
	}
	b.Run("single", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			if err := bob.Load(blob); err != nil {
				b.Fatal(err)
			}
			if err := bob.approve([]Leaf{carolLeaf}); err != nil {
				b.Fatal(err)
			}
			if _, err := bob.Process(commit); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("collect+enforce", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			if err := bob.Load(blob); err != nil {
				b.Fatal(err)
			}
			if _, err := bob.ProcessVerified(commit, trustAll{}); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// A damaged pool entry is refused with a fixed message: the entry holds two
// private keys, so the error names neither their bytes nor their size.
func TestAMalformedPoolEntryIsRefusedWithoutDescribingIt(t *testing.T) {
	s := newSession(t, "bob@device-1")
	_, pool, err := s.KeyPackages(1, uint64(time.Now().Add(time.Hour).Unix()))
	if err != nil {
		t.Fatal(err)
	}
	entry := pool[0].Private
	for _, bad := range [][]byte{entry[:len(entry)-1], append(bytes.Clone(entry), 0), {1, 2, 3}} {
		err := s.installKeyPackage(bad)
		if err == nil || !strings.HasSuffix(err.Error(), ": mls: key package entry is malformed") {
			t.Fatalf("install of a damaged entry = %v", err)
		}
	}
	if err := s.installKeyPackage(entry); err != nil {
		t.Fatalf("install of the real entry: %v", err)
	}
}
