package changetrack

import (
	"crypto/rand"
	"testing"
)

const (
	testOrgID   = "11111111-1111-4111-8111-111111111111"
	testGroupID = "22222222-2222-4222-8222-222222222222"
	testEntryA  = "33333333-3333-4333-8333-333333333333"
	testEntryB  = "44444444-4444-4444-8444-444444444444"
)

func testDEK(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return k
}

func groupScope(entry string) Scope {
	return Scope{Kind: ScopeGroup, ScopeID: testOrgID, GroupID: testGroupID, EntryID: entry}
}

// Test values are built in memory and never printed.
func TestCompare_SameValueIsSame(t *testing.T) {
	dek := testDEK(t)
	rec, err := Seal(rand.Reader, dek, groupScope(testEntryA), 3, 1, []byte("value-one"))
	if err != nil {
		t.Fatalf("seal failed")
	}
	if got := Compare(dek, groupScope(testEntryA), rec, []byte("value-one")); got != VerdictSame {
		t.Fatalf("verdict = %q, want same", got)
	}
}

func TestCompare_DifferentValueIsChanged(t *testing.T) {
	dek := testDEK(t)
	rec, err := Seal(rand.Reader, dek, groupScope(testEntryA), 3, 1, []byte("value-one"))
	if err != nil {
		t.Fatalf("seal failed")
	}
	if got := Compare(dek, groupScope(testEntryA), rec, []byte("value-two")); got != VerdictChanged {
		t.Fatalf("verdict = %q, want changed", got)
	}
}

// A record that cannot be verified is unknown, never changed.
func TestCompare_UnverifiableRecordIsUnknown(t *testing.T) {
	dek := testDEK(t)
	value := []byte("value-one")
	rec, err := Seal(rand.Reader, dek, groupScope(testEntryA), 3, 7, value)
	if err != nil {
		t.Fatalf("seal failed")
	}
	damaged := rec
	damaged.Ciphertext = append([]byte(nil), rec.Ciphertext...)
	damaged.Ciphertext[0] ^= 0x01
	otherVersion, otherSeq := rec, rec
	otherVersion.DekVersion = 4
	otherSeq.Seq = 6
	personal := Scope{Kind: ScopePersonal, ScopeID: testOrgID, EntryID: testEntryA}

	cases := []struct {
		name  string
		dek   []byte
		scope Scope
		rec   Sealed
	}{
		{"other entry", dek, groupScope(testEntryB), rec},
		{"other scope kind", dek, personal, rec},
		{"other dek version", dek, groupScope(testEntryA), otherVersion},
		{"other sequence", dek, groupScope(testEntryA), otherSeq},
		{"damaged ciphertext", dek, groupScope(testEntryA), damaged},
		{"wrong dek", testDEK(t), groupScope(testEntryA), rec},
		{"no dek", nil, groupScope(testEntryA), rec},
		{"empty record", dek, groupScope(testEntryA), Sealed{DekVersion: 3, Seq: 7}},
	}
	for _, tc := range cases {
		if got := Compare(tc.dek, tc.scope, tc.rec, value); got != VerdictUnknown {
			t.Errorf("%s: verdict = %q, want unknown", tc.name, got)
		}
	}
}

func TestCompare_UnsupportedFormatIsUnknown(t *testing.T) {
	dek := testDEK(t)
	s := groupScope(testEntryA)
	aad, err := recordAAD(s, 3, 1)
	if err != nil {
		t.Fatal(err)
	}
	plain := make([]byte, recordBytes)
	plain[0] = 0x02
	iv, ct, err := sealForTest(dek, plain, aad)
	if err != nil {
		t.Fatal(err)
	}
	rec := Sealed{IV: iv, Ciphertext: ct, DekVersion: 3, Seq: 1}
	if got := Compare(dek, s, rec, []byte("value-one")); got != VerdictUnknown {
		t.Fatalf("verdict = %q, want unknown", got)
	}
}

// Two entries holding the same value must not be linkable by their records.
func TestSeal_SameValueInTwoEntriesHasUnrelatedTags(t *testing.T) {
	dek := testDEK(t)
	value := []byte("shared-value")
	a, err := Seal(rand.Reader, dek, groupScope(testEntryA), 3, 1, value)
	if err != nil {
		t.Fatal("seal a failed")
	}
	b, err := Seal(rand.Reader, dek, groupScope(testEntryB), 3, 1, value)
	if err != nil {
		t.Fatal("seal b failed")
	}
	tagA := openTagForTest(t, dek, groupScope(testEntryA), a)
	tagB := openTagForTest(t, dek, groupScope(testEntryB), b)
	if string(tagA) == string(tagB) {
		t.Fatal("equal values in two entries produced equal tags")
	}
	again, err := Seal(rand.Reader, dek, groupScope(testEntryA), 3, 2, value)
	if err != nil {
		t.Fatal("reseal failed")
	}
	if string(openTagForTest(t, dek, groupScope(testEntryA), again)) == string(tagA) {
		t.Fatal("two versions of one entry share a comparison tag")
	}
}

func TestSeal_RefusesMalformedScope(t *testing.T) {
	dek := testDEK(t)
	bad := []struct {
		name string
		s    Scope
		ver  int
		seq  uint64
	}{
		{"unknown kind", Scope{Kind: "team", ScopeID: testOrgID, GroupID: testGroupID, EntryID: testEntryA}, 1, 1},
		{"uppercase entry", Scope{Kind: ScopeGroup, ScopeID: testOrgID, GroupID: testGroupID, EntryID: "33333333-3333-4333-8333-33333333333A"}, 1, 1},
		{"separator in id", Scope{Kind: ScopeGroup, ScopeID: testOrgID, GroupID: testGroupID, EntryID: "33333333|3333-4333-8333-333333333333"}, 1, 1},
		{"group without group id", Scope{Kind: ScopeGroup, ScopeID: testOrgID, EntryID: testEntryA}, 1, 1},
		{"personal with group id", Scope{Kind: ScopePersonal, ScopeID: testOrgID, GroupID: testGroupID, EntryID: testEntryA}, 1, 1},
		{"zero dek version", groupScope(testEntryA), 0, 1},
		{"zero sequence", groupScope(testEntryA), 1, 0},
	}
	for _, tc := range bad {
		if _, err := Seal(rand.Reader, dek, tc.s, tc.ver, tc.seq, []byte("v")); err == nil {
			t.Errorf("%s: seal accepted a malformed scope", tc.name)
		}
	}
}
